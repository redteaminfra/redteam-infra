# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import re
import hashlib
import json
import tempfile
import threading
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Mapping
from uuid import uuid4

from app.core.runtime import runtime_value, start_runtime_task
from app.domain import JobEvent, JobRunDetail
from app.services.teardown_target_contract import teardown_target_sha256
from app.integrations.ansible_disposable_validation import (
    SSH_PRIVATE_KEY_ENV,
    SSH_PUBLIC_KEY_ENV,
    SSH_SOURCE_CIDR_ENV,
    SSH_CONNECT_TIMEOUT_SECONDS,
    SSH_KNOWN_HOSTS_RELATIVE_PATH,
    SSH_READINESS_SLEEP_SECONDS,
    SSH_READINESS_TIMEOUT_SECONDS,
    VALIDATION_INSTANCE_NAME,
    WORKSPACE_NAME,
    build_ansible_validation_commands,
    build_ansible_validation_workspace,
    execute_disposable_ansible_validation,
    resolve_ansible,
    resolve_ansible_playbook,
)
from app.integrations.command_resolution import CommandResolution
from app.integrations.oci_disposable_terraform import (
    EXECUTION_CONFIRMATION,
    resolve_terraform,
)
from app.integrations.oci_read_validation import (
    NO_TOUCH_COMPARTMENT_NAMES,
    OciDevelopmentTarget,
    resolve_oci_cli,
)
from app.integrations.oci_compute_profiles import oci_compute_profile_from_snapshot
from app.integrations.oci_deployment_targets import (
    BARRAGAN_TESTING_TARGET,
    OciDeploymentTarget,
    OciDeploymentTargetError,
    allowed_oci_deployment_targets,
    resolve_oci_deployment_target,
)
from app.integrations.pilot_standard_rti import (
    CORE_MANAGEMENT_SSH_USER,
    DEFAULT_SSH_USER,
    DEFAULT_OPERATOR_SSH_SOURCE_CIDRS,
    DESTROY_AFTER_VALIDATION,
    HOLD_FOR_REVIEW,
    PILOT_HOMEBASE_PRIVATE_IP,
    PILOT_PROXY02_PRIVATE_IP,
    PILOT_PROXY_PRIVATE_IP,
    SSH_SOURCE_CIDRS_ENV,
    WORKSPACE_NAME as PILOT_WORKSPACE_NAME,
    build_pilot_execution_commands,
    build_pilot_standard_rti_workspace,
    execute_pilot_standard_rti,
    execute_pilot_standard_rti_teardown,
    pilot_names,
    pilot_topology,
)
from app.services.engagements import get_engagement
from app.services.engagement_workspaces import (
    DEFAULT_TERRAFORM_STATE_ROOT,
    EngagementWorkspaceValidationError,
    core_deployment_state_path,
    prepare_core_deployment_run,
)
from app.services.infra_orientation import try_enqueue_infra_orientation_refresh
from app.services.observer_checks import (
    cleanup_inspector_for_infrastructure_teardown,
    ensure_continuous_inspector_ready,
    verify_retired_public_endpoints_for_teardown,
)
from app.services.post_core_sketch_continuation import (
    snapshot_pending_sketch_chain_ids,
    start_post_core_sketch_continuation,
)
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import SketchChainRepository

CLEANUP_ACKNOWLEDGEMENT_LABEL = "confirmDestroyCleanup"
MUTATION_SCOPE = "disposable compute plus harmless Ansible validation only"
DISALLOWED_RESOURCE_FAMILIES = [
    "Vault/KMS/secrets",
    "Autonomous DB",
    "Object Storage",
    "Functions",
    "DevOps",
    "OKE",
    "DNS",
    "certificates",
    "load balancers",
    "DRG",
    "VPN",
    "FastConnect",
    "peering",
]
HARMLESS_ANSIBLE_ACTIONS = ["ansible.builtin.ping", "gather_facts/setup"]
PILOT_MUTATION_SCOPE = (
    "disposable Standard RTI core deployment with homebase, proxy01, proxy02, and base host layout configuration"
)
PILOT_ANSIBLE_CONFIGURATION_ACTIONS = [
    "SSH readiness",
    "ansible.builtin.ping",
    "gather_facts/setup",
    "configure /dropbox NFS export and proxy mounts",
    "create /engagement workspace on homebase",
    "create /opt/proxy01 and /opt/proxy02 on homebase",
    "create proxy runtime directory",
]
OCI_IMDS_HARDENING = {
    "legacyEndpointsDisabled": True,
    "terraformAttribute": "instance_options.are_legacy_imds_endpoints_disabled",
    "requirement": "All Barragan-created OCI compute instances must disable legacy IMDSv1 endpoints and use IMDSv2-only metadata access.",
}
PILOT_JOB_ACTION = "pilot_standard_rti_guarded_execute"
CORE_RECREATE_FLAG = "recreateCore"
CORE_RECREATE_CONFIRMATION_LABEL = "recreateConfirmation"

ExecutionFunction = Callable[..., Any]
BackgroundRunner = Callable[[Callable[[], None]], None]


class GuardedDeploymentConfirmationError(ValueError):
    pass


UNTRUSTED_CORE_RUN_FIELDS = {
    "corePlanId",
    "preparedCoreRun",
    "runDirectory",
    "planPath",
    "terraformDataDir",
    "terraformStatePath",
    "terraformStateLocator",
    "workspaceDir",
    "renderDestination",
    "sshPrivateKeyPath",
    "sshPublicKeyPath",
}


def _reject_untrusted_core_run_fields(body: Mapping[str, Any]) -> None:
    supplied = sorted(key for key in UNTRUSTED_CORE_RUN_FIELDS if key in body)
    if supplied:
        raise GuardedDeploymentConfirmationError(
            "prepared core run evidence is server-managed and must not be supplied: " + ", ".join(supplied)
        )


def disposable_deployment_readiness(
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    target = OciDevelopmentTarget()
    terraform_resolution = resolve_terraform(env=env)
    oci_resolution = resolve_oci_cli(env=env)
    ansible_resolution = resolve_ansible(env=env)
    ansible_playbook_resolution = resolve_ansible_playbook(env=env)
    terraform_command = terraform_resolution.command or "terraform"
    oci_command = oci_resolution.command or "oci"
    ansible_command = ansible_resolution.command or "ansible"
    ansible_playbook_command = ansible_playbook_resolution.command or "ansible-playbook"
    ssh_source_cidr = _env_value(SSH_SOURCE_CIDR_ENV, env) or f"${SSH_SOURCE_CIDR_ENV}"
    preview_workspace = build_ansible_validation_workspace(
        target,
        oci_executable=oci_command,
    )

    return {
        "target": target.to_dict(),
        "workspace": WORKSPACE_NAME,
        "mutationScope": MUTATION_SCOPE,
        "expectedInstanceDisplayName": VALIDATION_INSTANCE_NAME,
        "confirmationToken": EXECUTION_CONFIRMATION,
        "cleanupAcknowledgement": {
            "field": CLEANUP_ACKNOWLEDGEMENT_LABEL,
            "required": True,
            "label": "Destroy immediately and verify cleanup before the run is considered complete.",
        },
        "commands": {
            "planned": build_ansible_validation_commands(
                preview_workspace,
                terraform_executable=terraform_command,
                ansible_executable=ansible_command,
                ansible_playbook_executable=ansible_playbook_command,
                ssh_source_cidr=ssh_source_cidr,
            ),
            "cleanupVerification": preview_workspace.cleanup["verificationCommands"],
        },
        "commandResolution": {
            "oci": _command_resolution_dict(oci_resolution),
            "terraform": _command_resolution_dict(terraform_resolution),
            "ansible": _command_resolution_dict(ansible_resolution),
            "ansiblePlaybook": _command_resolution_dict(ansible_playbook_resolution),
        },
        "sshKeyConfiguration": {
            "publicKeyEnv": SSH_PUBLIC_KEY_ENV,
            "privateKeyEnv": SSH_PRIVATE_KEY_ENV,
            "sourceCidrEnv": SSH_SOURCE_CIDR_ENV,
            "publicKeyConfigured": _configured(SSH_PUBLIC_KEY_ENV, env),
            "privateKeyConfigured": _configured(SSH_PRIVATE_KEY_ENV, env),
            "sourceCidrConfigured": _configured(SSH_SOURCE_CIDR_ENV, env),
        },
        "sshIngress": {
            "sourceCidrEnv": SSH_SOURCE_CIDR_ENV,
            "sourceCidrConfigured": _configured(SSH_SOURCE_CIDR_ENV, env),
            "allowsPublicInternet": False,
            "publicInternetCidr": "0.0.0.0/0",
            "requirement": "SSH ingress must use one trusted operator or runner source CIDR and must never use 0.0.0.0/0.",
        },
        "sshReadiness": {
            "bounded": True,
            "module": "ansible.builtin.wait_for_connection",
            "timeoutSeconds": SSH_READINESS_TIMEOUT_SECONDS,
            "sleepSeconds": SSH_READINESS_SLEEP_SECONDS,
            "connectTimeoutSeconds": SSH_CONNECT_TIMEOUT_SECONDS,
            "knownHostsPath": SSH_KNOWN_HOSTS_RELATIVE_PATH,
            "hostKeyPolicy": "accept-new in the disposable workspace only",
        },
        "imdsHardening": OCI_IMDS_HARDENING,
        "guardrails": {
            "allowedCompartment": target.name,
            "allowedCompartmentId": target.compartment_id,
            "allowedRegion": target.region,
            "noTouchCompartments": sorted(NO_TOUCH_COMPARTMENT_NAMES),
            "mutationBoundary": MUTATION_SCOPE,
            "harmlessAnsibleActions": HARMLESS_ANSIBLE_ACTIONS,
            "disallowedResourceFamilies": DISALLOWED_RESOURCE_FAMILIES,
        },
    }


def pilot_standard_rti_readiness(
    *,
    env: Mapping[str, str] | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_for_optional_id(engagement_id)
    engagement_name = engagement.name if engagement is not None else "pilot"
    target = _target_for_engagement(engagement)
    names = pilot_names(engagement_name)
    terraform_resolution = resolve_terraform(env=env)
    oci_resolution = resolve_oci_cli(env=env)
    ansible_resolution = resolve_ansible(env=env)
    ansible_playbook_resolution = resolve_ansible_playbook(env=env)
    terraform_command = terraform_resolution.command or "terraform"
    oci_command = oci_resolution.command or "oci"
    ansible_command = ansible_resolution.command or "ansible"
    ansible_playbook_command = ansible_playbook_resolution.command or "ansible-playbook"
    ssh_source_cidrs = _pilot_ssh_source_cidrs(env)
    preview_workspace = build_pilot_standard_rti_workspace(
        target,
        engagement_name=engagement_name,
        oci_executable=oci_command,
        proxy_count=_proxy_count_for_optional_engagement_id(engagement_id),
    )
    proxy_count = preview_workspace.proxy_count

    return {
        "target": target.to_dict(),
        "availableTargets": [candidate.to_dict() for candidate in allowed_oci_deployment_targets(_runtime_environment())],
        "workspace": PILOT_WORKSPACE_NAME,
        "mutationScope": PILOT_MUTATION_SCOPE,
        "expectedInstanceDisplayNames": [
            names.homebase_name,
            names.proxy_name,
            *([names.proxy02_name] if proxy_count == 2 else []),
        ],
        "topology": pilot_topology(names, proxy_count=proxy_count),
        "deploymentModes": {
            "default": HOLD_FOR_REVIEW,
            "supported": [HOLD_FOR_REVIEW, DESTROY_AFTER_VALIDATION],
        },
        "confirmationToken": _deployment_confirmation_token(engagement_name, target),
        "cleanupAcknowledgement": {
            "field": CLEANUP_ACKNOWLEDGEMENT_LABEL,
            "required": False,
            "label": "Immediate destroy is available for automated smoke tests. Operator deploys hold for inspection until Tear Down is requested.",
        },
        "commands": {
            "planned": build_pilot_execution_commands(
                preview_workspace,
                terraform_executable=terraform_command,
                ansible_executable=ansible_command,
                ansible_playbook_executable=ansible_playbook_command,
                ssh_source_cidrs=ssh_source_cidrs,
            ),
            "cleanupVerification": preview_workspace.cleanup["verificationCommands"],
        },
        "commandResolution": {
            "oci": _command_resolution_dict(oci_resolution),
            "terraform": _command_resolution_dict(terraform_resolution),
            "ansible": _command_resolution_dict(ansible_resolution),
            "ansiblePlaybook": _command_resolution_dict(ansible_playbook_resolution),
        },
        "sshKeyConfiguration": {
            "publicKeyEnv": SSH_PUBLIC_KEY_ENV,
            "privateKeyEnv": SSH_PRIVATE_KEY_ENV,
            "sourceCidrEnv": SSH_SOURCE_CIDR_ENV,
            "sourceCidrsEnv": SSH_SOURCE_CIDRS_ENV,
            "publicKeyConfigured": _configured(SSH_PUBLIC_KEY_ENV, env),
            "privateKeyConfigured": _configured(SSH_PRIVATE_KEY_ENV, env),
            "sourceCidrConfigured": bool(ssh_source_cidrs),
            "sourceCidrsConfigured": bool(ssh_source_cidrs),
        },
        "sshIngress": {
            "sourceCidrEnv": SSH_SOURCE_CIDR_ENV,
            "sourceCidrsEnv": SSH_SOURCE_CIDRS_ENV,
            "sourceCidrConfigured": bool(ssh_source_cidrs),
            "sourceCidrsConfigured": bool(ssh_source_cidrs),
            "defaultSourceCidrs": ssh_source_cidrs,
            "allowsPublicInternet": False,
            "publicInternetCidr": "0.0.0.0/0",
            "requirement": "SSH ingress must use trusted operator or runner source CIDRs and must never use 0.0.0.0/0.",
        },
        "sshReadiness": {
            "bounded": True,
            "module": "ansible.builtin.wait_for_connection",
            "timeoutSeconds": SSH_READINESS_TIMEOUT_SECONDS,
            "sleepSeconds": SSH_READINESS_SLEEP_SECONDS,
            "connectTimeoutSeconds": SSH_CONNECT_TIMEOUT_SECONDS,
            "knownHostsPath": SSH_KNOWN_HOSTS_RELATIVE_PATH,
            "hostKeyPolicy": "accept-new in the pilot workspace only",
        },
        "imdsHardening": OCI_IMDS_HARDENING,
        "guardrails": {
            "allowedCompartment": target.name,
            "allowedCompartmentId": target.compartment_id,
            "allowedRegion": target.region,
            "noTouchCompartments": sorted(NO_TOUCH_COMPARTMENT_NAMES),
            "mutationBoundary": PILOT_MUTATION_SCOPE,
            "harmlessAnsibleActions": PILOT_ANSIBLE_CONFIGURATION_ACTIONS,
            "disallowedResourceFamilies": DISALLOWED_RESOURCE_FAMILIES,
        },
    }


def run_guarded_disposable_deployment(
    body: Mapping[str, Any],
    *,
    executor: ExecutionFunction = execute_disposable_ansible_validation,
) -> dict[str, Any]:
    if body.get("confirmMutation") != EXECUTION_CONFIRMATION:
        raise GuardedDeploymentConfirmationError(
            f'confirmMutation must equal "{EXECUTION_CONFIRMATION}"'
        )
    if body.get(CLEANUP_ACKNOWLEDGEMENT_LABEL) is not True:
        raise GuardedDeploymentConfirmationError(
            f"{CLEANUP_ACKNOWLEDGEMENT_LABEL} must be true"
        )
    if str(body.get("sshSourceCidr", "")).strip() == "0.0.0.0/0":
        raise GuardedDeploymentConfirmationError("sshSourceCidr must not be 0.0.0.0/0")

    workspace_dir = _workspace_dir(body.get("workspaceDir") or body.get("renderDestination"))
    result = executor(
        workspace_dir,
        ssh_private_key_path=body.get("sshPrivateKeyPath"),
        ssh_public_key_path=body.get("sshPublicKeyPath"),
        ssh_source_cidr=body.get("sshSourceCidr"),
    )
    result_body = result.to_dict() if hasattr(result, "to_dict") else result
    return {"deployment": result_body}


def run_guarded_pilot_standard_rti(
    body: Mapping[str, Any],
    *,
    executor: ExecutionFunction = execute_pilot_standard_rti,
    engagement_workspace_root: Path = Path("/opt/engagements"),
    terraform_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    allow_legacy_internal: bool = True,
) -> dict[str, Any]:
    from app.services.engagement_teardown import assert_core_creation_allowed

    if not str(body.get("engagementId") or "").strip() and body.get("confirmMutation") != EXECUTION_CONFIRMATION:
        raise GuardedDeploymentConfirmationError(
            f'confirmMutation must equal "{EXECUTION_CONFIRMATION}"'
        )
    if not allow_legacy_internal:
        _reject_untrusted_core_run_fields(body)
    engagement_id = str(body.get("engagementId") or "").strip()
    if engagement_id:
        try:
            assert_core_creation_allowed(engagement_id)
        except RuntimeError as exc:
            # Pure service tests may inject every dependency without binding a
            # runtime database. A real mutation cannot proceed without that
            # context because engagement/workspace resolution also requires it.
            if "no database context is active" not in str(exc):
                raise
    engagement = _required_engagement(body)
    target = _target_for_engagement(engagement)
    _validate_guarded_pilot_request(body, engagement, target)
    if not allow_legacy_internal:
        raise GuardedDeploymentConfirmationError(
            "direct core deployment is disabled; prepare and apply an exact saved deployment plan"
        )
    durable_run = prepare_core_deployment_run(
        str(engagement.id), root=engagement_workspace_root, state_root=terraform_state_root, run_id=f"core-{uuid4().hex}"
    )
    result = executor(
        durable_run.run_directory,
        target=target,
        ssh_private_key_path=body.get("sshPrivateKeyPath"),
        ssh_public_key_path=body.get("sshPublicKeyPath"),
        ssh_source_cidrs=_request_ssh_source_cidrs(body),
        deployment_mode=_request_deployment_mode(body),
        engagement_name=engagement.name,
        engagement_id=str(engagement.id),
        proxy_count=_proxy_count_for_engagement(engagement),
        terraform_state_path=durable_run.state_path,
        terraform_data_dir=durable_run.terraform_data_dir,
    )
    result_body = result.to_dict() if hasattr(result, "to_dict") else result
    return {"deployment": result_body}


def start_guarded_pilot_standard_rti_run(
    body: Mapping[str, Any],
    *,
    executor: ExecutionFunction = execute_pilot_standard_rti,
    repository: JobRepository | None = None,
    background_runner: BackgroundRunner | None = None,
    engagement_workspace_root: Path = Path("/opt/engagements"),
    terraform_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    sketch_repository: SketchChainRepository | None = None,
    prepared_core_run: Mapping[str, Any] | None = None,
    core_plan_id: str = "",
    core_plan_revision_id: str = "",
) -> JobRunDetail:
    engagement = _required_engagement(body)
    target = _target_for_engagement(engagement)
    _validate_guarded_pilot_request(body, engagement, target)
    repo = repository or SqlAlchemyJobRepository()
    from app.services.engagement_teardown import assert_core_creation_allowed
    assert_core_creation_allowed(str(engagement.id), repository=repo)
    internal_legacy = repository is not None and not isinstance(repo, SqlAlchemyJobRepository)
    if not internal_legacy:
        _reject_untrusted_core_run_fields(body)
    prepared = dict(prepared_core_run) if prepared_core_run is not None else None
    if prepared is not None and not core_plan_id:
        raise GuardedDeploymentConfirmationError("trusted prepared core run requires a verified core plan id")
    if prepared is not None and prepared.get("sketchStateSchema") == "provider-keyed-v2" and not core_plan_revision_id:
        raise GuardedDeploymentConfirmationError("keyed core run requires the reviewed revision id")
    keyed_source_pin = (
        _require_configured_keyed_source()
        if prepared is not None and prepared.get("sketchStateSchema") == "provider-keyed-v2"
        else None
    )
    if not prepared and body.get(CORE_RECREATE_FLAG) is not True and not internal_legacy:
        raise GuardedDeploymentConfirmationError(
            "corePlanId is required; prepare and apply an exact saved deployment plan"
        )
    _validate_core_recreate_guard(body, engagement.name, str(engagement.id), repo)
    legacy_lease_owner = ""
    if not prepared and not internal_legacy:
        from app.storage.deployment_plan_repository import (
            DeploymentPlanConflictError,
            SqlAlchemyDeploymentPlanRepository,
        )

        legacy_lease_owner = f"legacy-{uuid4().hex}"
        try:
            SqlAlchemyDeploymentPlanRepository().acquire(str(engagement.id), legacy_lease_owner, "recreate")
        except DeploymentPlanConflictError as exc:
            raise GuardedDeploymentConfirmationError("another core mutation is already in progress") from exc
    if prepared:
        from types import SimpleNamespace

        durable_run = SimpleNamespace(
            run_directory=Path(str(prepared["runDirectory"])),
            state_path=Path(str(prepared["terraformStatePath"])),
            terraform_data_dir=Path(str(prepared["terraformDataDir"])),
            state_locator=str(prepared["terraformStateLocator"]),
        )
    else:
        try:
            durable_run = prepare_core_deployment_run(
                str(engagement.id), root=engagement_workspace_root, state_root=terraform_state_root, run_id=f"core-{uuid4().hex}"
            )
        except Exception:
            _release_core_mutation_lease(str(engagement.id), legacy_lease_owner)
            raise
    workspace_dir = durable_run.run_directory
    proxy_count = _proxy_count_for_engagement(engagement)
    pending_sketch_chain_ids = (
        [str(value) for value in prepared.get("pendingSketchChainIds", []) if str(value).strip()]
        if prepared
        else (
            snapshot_pending_sketch_chain_ids(str(engagement.id), repository=sketch_repository)
            if sketch_repository is not None or isinstance(repo, SqlAlchemyJobRepository)
            else []
        )
    )
    job_body = {
        **dict(body),
        "corePlanId": core_plan_id or None,
        "sketchStateSchema": str(prepared.get("sketchStateSchema") or "split-v1") if prepared else "split-v1",
        "terraformStateLocator": durable_run.state_locator,
        "pendingSketchChainIds": pending_sketch_chain_ids,
        "pendingSketchChainFingerprints": dict(prepared.get("pendingSketchChainFingerprints") or {}) if prepared else {},
        "templateId": str(prepared.get("templateId") or engagement.template_id or "standard-rti") if prepared else str(engagement.template_id or "standard-rti"),
        "elkEnabled": bool(prepared.get("elkEnabled")) if prepared else bool((engagement.input_parameters or {}).get("elkEnabled")),
        "computeProfileSnapshot": dict(prepared.get("computeProfileSnapshot") or {}) if prepared else {},
        **({"providerKeyedSourcePin": keyed_source_pin} if keyed_source_pin is not None else {}),
        **({"corePlanEvidenceSha256": hashlib.sha256(json.dumps(prepared, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
           if keyed_source_pin is not None else {}),
    }
    queued = _new_pilot_job(job_body, workspace_dir, engagement.name, proxy_count, target)
    keyed_reservation = bool(prepared and prepared.get("sketchStateSchema") == "provider-keyed-v2")

    def mark_reserved_attention() -> None:
        if keyed_reservation:
            from app.services.core_deployment_plans import mark_bound_keyed_core_start_attention
            mark_bound_keyed_core_start_attention(core_plan_id, str(engagement.id), queued.id)

    if keyed_reservation:
        if not isinstance(repo, SqlAlchemyJobRepository):
            raise GuardedDeploymentConfirmationError("keyed core reservation requires the durable job repository")
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository

        # The queued job and apply_job_id become visible together. In particular,
        # a synchronous worker cannot finish before the plan knows its identity.
        SqlAlchemyDeploymentPlanRepository().reserve_keyed_core_apply_job(
            queued, expected_evidence=prepared, expected_revision_id=core_plan_revision_id,
        )
        try:
            job = repo.get(queued.id)
            if job is None:
                raise GuardedDeploymentConfirmationError("keyed core reservation was not retained")
        except Exception:
            mark_reserved_attention()
            raise
    else:
        job = repo.save(queued)
    try:
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
                        "pilot Standard RTI run started",
                        (
                            {"workspace": PILOT_WORKSPACE_NAME}
                            if core_plan_id
                            else {"workspace": PILOT_WORKSPACE_NAME, "workspaceDir": str(workspace_dir)}
                        ),
                    )
                ],
            )
        )
    except Exception:
        mark_reserved_attention()
        raise
    _reconcile_core_lifecycle_best_effort(str(engagement.id), repo, "core_deployment_started")

    runner = background_runner or _start_background_task
    execution_body = {
        **dict(body),
        "engagementName": engagement.name,
        "proxyCount": proxy_count,
        "terraformStatePath": str(durable_run.state_path),
        "terraformDataDir": str(durable_run.terraform_data_dir),
        "terraformStateLocator": durable_run.state_locator,
        "target": target.to_dict(),
        "corePlanId": core_plan_id,
        "preparedPlanPath": str(prepared.get("planPath") or "") if prepared else "",
        "templateId": str(prepared.get("templateId") or engagement.template_id or "standard-rti") if prepared else str(engagement.template_id or "standard-rti"),
        "elkEnabled": bool(prepared.get("elkEnabled")) if prepared else bool((engagement.input_parameters or {}).get("elkEnabled")),
        "computeProfileSnapshot": dict(prepared.get("computeProfileSnapshot") or {}) if prepared else {},
        "coreMutationLeaseOwner": legacy_lease_owner,
        "sshPrivateKeyPath": prepared.get("sshPrivateKeyPath") if prepared else body.get("sshPrivateKeyPath"),
        "sshPublicKeyPath": prepared.get("sshPublicKeyPath") if prepared else body.get("sshPublicKeyPath"),
    }
    try:
        runner(
            lambda: _execute_guarded_pilot_standard_rti_run(
                running.id,
                execution_body,
                workspace_dir,
                executor=executor,
                repository=repo,
            )
        )
    except Exception:
        mark_reserved_attention()
        _release_core_mutation_lease(str(engagement.id), legacy_lease_owner)
        raise
    detail = running.to_detail()
    return _sanitize_core_plan_job_detail(detail) if core_plan_id else detail


def _execute_guarded_pilot_standard_rti_run(
    job_id: str,
    body: Mapping[str, Any],
    workspace_dir: Path,
    *,
    executor: ExecutionFunction,
    repository: JobRepository,
) -> JobRunDetail | None:
    job = repository.get(job_id)
    if job is None:
        return None

    job = _append_pilot_job_event(
        repository,
        job,
        "info",
        "readiness and guardrails accepted",
        ({"workspace": PILOT_WORKSPACE_NAME} if body.get("corePlanId") else {"workspace": PILOT_WORKSPACE_NAME, "workspaceDir": str(workspace_dir)}),
    )
    job = _append_pilot_job_event(
        repository,
        job,
        "info",
        "pilot Standard RTI executor running",
        ({"workspace": PILOT_WORKSPACE_NAME} if body.get("corePlanId") else {"workspace": PILOT_WORKSPACE_NAME, "workspaceDir": str(workspace_dir)}),
    )

    def record_progress(event: Mapping[str, Any]) -> None:
        nonlocal job
        if (job.input.get("sketchStateSchema") == "provider-keyed-v2"
                and isinstance(event.get("data"), Mapping)
                and event["data"].get("eventKind") == "command_started"
                and event["data"].get("step") == "terraform_apply"):
            # The upstream executor emits this synchronously before Popen.
            # Source and every saved-plan input are checked again at GO.
            _require_configured_keyed_source(job.input.get("providerKeyedSourcePin"))
            from app.services.core_deployment_plans import _verify_plan_evidence
            from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
            from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

            plan_id = job.input.get("corePlanId")
            plan = SqlAlchemyDeploymentPlanRepository().get(plan_id) if isinstance(plan_id, str) else None
            if (plan is None or plan.status != "applying" or plan.apply_job_id != job.id
                    or plan.engagement_id != job.input.get("engagementId")
                    or _db_lease_lookup(plan.engagement_id) != (plan.id, "apply")
                    or job.input.get("corePlanEvidenceSha256") != hashlib.sha256(
                        json.dumps(plan.evidence, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()):
                raise GuardedDeploymentConfirmationError("reviewed keyed core plan changed before apply")
            _verify_plan_evidence(plan)
        message = str(event.get("message") or "pilot Standard RTI progress updated")
        level = str(event.get("level") or "info")
        data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
        if body.get("corePlanId"):
            data = _sanitize_core_plan_event_data(data)
        job = _append_pilot_job_event(
            repository,
            job,
            level,
            message,
            dict(data),
        )

    try:
        result = executor(
            workspace_dir,
            target=resolve_oci_deployment_target(body.get("target"), environment=_runtime_environment()),
            ssh_private_key_path=body.get("sshPrivateKeyPath"),
            ssh_public_key_path=body.get("sshPublicKeyPath"),
            ssh_source_cidrs=_request_ssh_source_cidrs(body),
            deployment_mode=_request_deployment_mode(body),
            engagement_name=str(body.get("engagementName") or ""),
            engagement_id=str(body.get("engagementId") or ""),
            proxy_count=_proxy_count_from_value(body.get("proxyCount")),
            template_id=str(body.get("templateId") or "standard-rti"),
            elk_enabled=body.get("elkEnabled") is True,
            compute_profile=(
                oci_compute_profile_from_snapshot(body["computeProfileSnapshot"])
                if isinstance(body.get("computeProfileSnapshot"), Mapping) and body.get("computeProfileSnapshot")
                else None
            ),
            terraform_state_path=body.get("terraformStatePath"),
            terraform_data_dir=body.get("terraformDataDir"),
            progress_callback=record_progress,
            prepared_plan_path=body.get("preparedPlanPath") or None,
        )
    except Exception as exc:
        failed_events = job.events + [
            JobEvent(
                _next_sequence(job.events),
                "error",
                "pilot Standard RTI run failed before a result was returned",
                _sanitize_core_plan_event_data({
                    "error": _redacted_exception_message(exc, body),
                    "errorType": type(exc).__name__,
                    "workspace": PILOT_WORKSPACE_NAME,
                    "workspaceDir": str(workspace_dir),
                }) if body.get("corePlanId") else {
                    "error": _redacted_exception_message(exc, body),
                    "errorType": type(exc).__name__,
                    "workspace": PILOT_WORKSPACE_NAME,
                    "workspaceDir": str(workspace_dir),
                },
            )
        ]
        failed = repository.save(
            replace(
                job,
                status="failed",
                finished_at=_now(),
                events=failed_events,
                artifact_refs=[f"workspace:{workspace_dir}"],
            )
        )
        _reconcile_core_lifecycle_best_effort(str(failed.input.get("engagementId") or failed.target_id), repository, "core_deployment_failed")
        if failed.input.get("corePlanId"):
            from app.services.core_deployment_plans import finish_core_deployment_plan_apply
            finish_core_deployment_plan_apply(str(failed.input["corePlanId"]), succeeded=False)
        _release_core_mutation_lease(str(body.get("engagementId") or ""), str(body.get("coreMutationLeaseOwner") or ""))
        return failed.to_detail()

    result_body = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    final_status = "succeeded" if result_body.get("ok") is True else "failed"
    continuous_inspector_required = (
        final_status == "succeeded"
        and _should_enqueue_orientation_refresh_for_core_result(result_body)
        and _is_runtime_durable_job_repository(repository)
    )
    if continuous_inspector_required:
        job = _append_pilot_job_event(
            repository,
            job,
            "info",
            "continuous Inspector readiness started",
            {"status": "preparing", "engagementId": str(job.input.get("engagementId") or job.target_id)},
        )
    final_events = _dedupe_job_events(
        job.events,
        _pilot_result_events(
            result_body,
            _next_sequence(job.events),
            include_guardrail_event=False,
            include_operator_inspection_ready=not continuous_inspector_required,
            include_finished=not continuous_inspector_required,
        ),
    )
    if body.get("corePlanId"):
        final_events = [replace(event, data=_sanitize_core_plan_event_data(event.data)) for event in final_events]
    inspector_readiness: dict[str, Any] | None = None
    if final_status == "succeeded" and continuous_inspector_required:
        try:
            inspector_readiness = ensure_continuous_inspector_ready(
                str(job.input.get("engagementId") or job.target_id),
                requested_by="core-deployment",
                job_repository=repository,
            )
        except Exception as exc:
            inspector_readiness = {
                "required": True,
                "ready": False,
                "status": "failed",
                "errors": [_redacted_exception_message(exc, body)],
            }
        if inspector_readiness.get("ready") is not True:
            final_status = "failed"
            final_events.append(
                JobEvent(
                    _next_sequence([*job.events, *final_events]),
                    "error",
                    "continuous Inspector readiness failed; deployed core is retained",
                    _sanitize_core_plan_event_data(inspector_readiness) if body.get("corePlanId") else inspector_readiness,
                )
            )
            final_events.extend(
                _pilot_result_events(
                    {**result_body, "ok": False},
                    _next_sequence([*job.events, *final_events]),
                    include_guardrail_event=False,
                    include_preflight_event=False,
                    include_command_events=False,
                    include_operator_inspection_ready=False,
                )
            )
        else:
            final_events.append(
                JobEvent(
                    _next_sequence([*job.events, *final_events]),
                    "info",
                    "continuous Inspector readiness succeeded",
                    _sanitize_core_plan_event_data(inspector_readiness) if body.get("corePlanId") else inspector_readiness,
                )
            )
            final_events.extend(
                _pilot_result_events(
                    result_body,
                    _next_sequence([*job.events, *final_events]),
                    include_guardrail_event=False,
                    include_preflight_event=False,
                    include_command_events=False,
                )
            )
    def keyed_completion_attention() -> JobRunDetail:
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository

        SqlAlchemyDeploymentPlanRepository().fail_keyed_core_completion(
            job.id, str(job.input.get("corePlanId") or ""),
            str(job.input.get("engagementId") or ""),
        )
        failed = repository.get(job.id)
        if failed is None:
            raise GuardedDeploymentConfirmationError("keyed core attention was not retained")
        _reconcile_core_lifecycle_best_effort(
            str(failed.input.get("engagementId") or failed.target_id), repository,
            "core_deployment_failed",
        )
        return failed.to_detail()

    if final_status == "succeeded" and job.input.get("sketchStateSchema") == "provider-keyed-v2":
        from app.storage.deployment_plan_repository import (
            DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository,
            _OCI_CORE_STATE_SEAL_MESSAGE, _keyed_core_state_seal_event_data,
            _read_keyed_core_state_seal,
        )

        try:
            plan = SqlAlchemyDeploymentPlanRepository().get(str(job.input.get("corePlanId") or ""))
            if (plan is None or plan.status != "applying" or plan.apply_job_id != job.id
                    or plan.engagement_id != job.input.get("engagementId")):
                raise DeploymentPlanConflictError("reviewed keyed core plan changed before state seal")
            seal = _read_keyed_core_state_seal(plan.evidence, job.input)
            if not final_events or final_events[-1].message != "pilot Standard RTI run finished":
                raise DeploymentPlanConflictError("keyed core terminal event is missing")
            final_events.insert(-1, JobEvent(0, "info", _OCI_CORE_STATE_SEAL_MESSAGE,
                                             _keyed_core_state_seal_event_data(seal)))
            final_events = [replace(event, sequence=len(job.events) + index + 1)
                            for index, event in enumerate(final_events)]
        except Exception:
            return keyed_completion_attention()
    finished = replace(
        job,
        status=final_status,
        finished_at=_now(),
        input={
            **job.input,
            "inspectorReadiness": inspector_readiness or {},
            "postCoreSketchContinuationEligible": final_status == "succeeded"
            and _should_enqueue_orientation_refresh_for_core_result(result_body)
            and job.input.get("sketchStateSchema", "split-v1") != "provider-keyed-v2",
            **({"providerKeyedDispatchAuthorized": (
                _runtime_environment() == "devtest"
                and runtime_value("PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED", False) is True
            )} if job.input.get("sketchStateSchema") == "provider-keyed-v2" else {}),
        },
        artifact_refs=[f"workspace:{workspace_dir}"],
        events=job.events + final_events,
    )
    if final_status == "succeeded" and job.input.get("sketchStateSchema") == "provider-keyed-v2":
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository

        if not isinstance(repository, SqlAlchemyJobRepository):
            raise GuardedDeploymentConfirmationError("keyed core completion requires the durable job repository")
        try:
            SqlAlchemyDeploymentPlanRepository().finish_keyed_core_success(finished)
        except Exception:
            return keyed_completion_attention()
        saved = repository.get(job.id)
        if saved is None:
            raise GuardedDeploymentConfirmationError("keyed core completion was not retained")
    else:
        saved = repository.save(finished)
        if saved.input.get("corePlanId"):
            from app.services.core_deployment_plans import finish_core_deployment_plan_apply
            finish_core_deployment_plan_apply(str(saved.input["corePlanId"]), succeeded=saved.status == "succeeded")
    _release_core_mutation_lease(str(body.get("engagementId") or ""), str(body.get("coreMutationLeaseOwner") or ""))
    _reconcile_core_lifecycle_best_effort(str(saved.input.get("engagementId") or saved.target_id), repository, "core_deployment_finished")
    if saved.status == "succeeded" and _should_enqueue_orientation_refresh_for_core_result(result_body):
        try_enqueue_infra_orientation_refresh(str(saved.input.get("engagementId") or saved.target_id), repository=repository)
        if saved.input.get("postCoreSketchContinuationEligible") and saved.input.get("pendingSketchChainIds"):
            start_post_core_sketch_continuation(saved.id, job_repository=repository)
    if (saved.status == "succeeded"
            and saved.input.get("sketchStateSchema") == "provider-keyed-v2"
            and _runtime_environment() == "devtest"
            and runtime_value("PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED", False) is True):
        _route_keyed_core_after_success(saved)
    return saved.to_detail()


def _route_keyed_core_after_success(saved) -> None:
    """Use the reviewed plan kind to retain one Deploy action across core success."""
    from app.services.provider_keyed_mixed_initial_public import (
        advance_reviewed_mixed_initial, is_reviewed_mixed_initial,
    )
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository

    reviewed = SqlAlchemyDeploymentPlanRepository().get(saved.input.get("corePlanId"))
    if reviewed is not None and is_reviewed_mixed_initial(reviewed):
        advance_reviewed_mixed_initial(
            saved.id, environment="devtest", rollout_enabled=True)
    else:
        from app.services.provider_keyed_initial_dispatch import _recover_one

        _recover_one(saved.id, environment="devtest", rollout_enabled=True)


def _should_enqueue_orientation_refresh_for_core_result(result_body: Mapping[str, Any]) -> bool:
    """Orientation refresh writes to homebase, so it only applies to live core deployments."""

    return (
        result_body.get("deploymentMode") == HOLD_FOR_REVIEW
        and result_body.get("mutationStatus") == "deployed"
        and result_body.get("ansibleStatus") == "validated"
        and result_body.get("finalCleanupStatus") == "pending_operator_teardown"
    )


def _is_runtime_durable_job_repository(repository: JobRepository) -> bool:
    """Keep legacy injected job repositories independent of runtime providers."""
    return isinstance(repository, SqlAlchemyJobRepository)


def get_guarded_pilot_standard_rti_run(
    job_id: str,
    *,
    repository: JobRepository | None = None,
) -> JobRunDetail | None:
    job = (repository or SqlAlchemyJobRepository()).get(job_id)
    if job is None or job.action != PILOT_JOB_ACTION:
        return None
    detail = _job_detail_with_connection_details(job)
    return _sanitize_core_plan_job_detail(detail) if job.input.get("corePlanId") else detail


def start_guarded_pilot_standard_rti_teardown(
    job_id: str,
    *,
    executor: ExecutionFunction = execute_pilot_standard_rti_teardown,
    repository: JobRepository | None = None,
    background_runner: BackgroundRunner | None = None,
    engagement_workspace_root: Path = Path("/opt/engagements"),
    terraform_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
    verification_targets: list[dict[str, Any]] | None = None,
) -> JobRunDetail | None:
    repo = repository or SqlAlchemyJobRepository()
    job = repo.get(job_id)
    if job is None or job.action != PILOT_JOB_ACTION:
        return None
    workspace_dir_value = str(job.input.get("workspaceDir") or "").strip()
    if not workspace_dir_value:
        return None
    workspace_dir = Path(workspace_dir_value)
    queued_at = _now()
    running = repo.save(
        replace(
            job,
            status="running",
            finished_at=None,
            input={
                **job.input,
                **({"engagementTeardownVerificationTargets": [dict(target) for target in verification_targets]} if verification_targets is not None else {}),
            },
            events=job.events
            + [
                JobEvent(
                    _next_sequence(job.events),
                    "info",
                    "operator teardown queued",
                    {
                        "workspace": PILOT_WORKSPACE_NAME,
                        "workspaceDir": str(workspace_dir),
                        "requestedAt": queued_at,
                    },
                )
            ],
        )
    )
    _reconcile_core_lifecycle_best_effort(str(running.input.get("engagementId") or running.target_id), repo, "core_teardown_started")
    task_runner = background_runner or _start_background_task
    task_runner(
        lambda: teardown_guarded_pilot_standard_rti_run(
            job_id, executor=executor, repository=repo,
            engagement_workspace_root=engagement_workspace_root, terraform_state_root=terraform_state_root,
        )
    )
    return running.to_detail()


def teardown_guarded_pilot_standard_rti_run(
    job_id: str,
    *,
    executor: ExecutionFunction = execute_pilot_standard_rti_teardown,
    repository: JobRepository | None = None,
    engagement_workspace_root: Path = Path("/opt/engagements"),
    terraform_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
) -> JobRunDetail | None:
    repo = repository or SqlAlchemyJobRepository()
    job = repo.get(job_id)
    if job is None or job.action != PILOT_JOB_ACTION:
        return None
    workspace_dir_value = str(job.input.get("workspaceDir") or "").strip()
    if not workspace_dir_value:
        return None
    workspace_dir = Path(workspace_dir_value)
    teardown_started = datetime.now(timezone.utc)
    last_progress_at = teardown_started
    job = _append_pilot_job_event(
        repo,
        job,
        "info",
        "operator teardown requested",
        {
            "workspace": PILOT_WORKSPACE_NAME,
            "workspaceDir": str(workspace_dir),
            "startedAt": teardown_started.isoformat(),
        },
    )

    def record_progress(event: Mapping[str, Any]) -> None:
        nonlocal job, last_progress_at
        observed_at = datetime.now(timezone.utc)
        message = str(event.get("message") or "pilot Standard RTI teardown progress updated")
        level = str(event.get("level") or "info")
        data = event.get("data") if isinstance(event.get("data"), Mapping) else {}
        timing = {
            "startedAt": last_progress_at.isoformat(),
            "finishedAt": observed_at.isoformat(),
            "durationSeconds": round((observed_at - last_progress_at).total_seconds(), 3),
        }
        job = _append_pilot_job_event(repo, job, level, message, {**dict(data), "timing": timing})
        last_progress_at = observed_at

    prior_cleanup = _prior_verified_core_cleanup(job, workspace_dir)
    try:
        result = None if prior_cleanup else executor(
            workspace_dir,
            target=resolve_oci_deployment_target(job.input.get("target"), environment=_runtime_environment()),
            ssh_source_cidrs=list(job.input.get("sshSourceCidrs") or []),
            engagement_name=str(job.input.get("engagementName") or ""),
            engagement_id=str(job.input.get("engagementId") or job.target_id),
            proxy_count=_proxy_count_from_value(job.input.get("proxyCount")),
            template_id=str(job.input.get("templateId") or "standard-rti"),
            elk_enabled=job.input.get("elkEnabled") is True,
            compute_profile=(
                oci_compute_profile_from_snapshot(job.input["computeProfileSnapshot"])
                if isinstance(job.input.get("computeProfileSnapshot"), Mapping) and job.input.get("computeProfileSnapshot")
                else None
            ),
            terraform_state_path=_teardown_terraform_state_path(
                job,
                workspace_dir=workspace_dir,
                engagement_workspace_root=engagement_workspace_root,
                terraform_state_root=terraform_state_root,
            ),
            progress_callback=record_progress,
        )
    except Exception as exc:
        failed = repo.save(
            replace(
                job,
                status="failed",
                finished_at=_now(),
                events=job.events
                + [
                    JobEvent(
                        _next_sequence(job.events),
                        "error",
                        "pilot Standard RTI teardown failed before a result was returned",
                        {
                            "error": _redacted_exception_message(exc, job.input),
                            "errorType": type(exc).__name__,
                            "timing": _timing_from(teardown_started),
                        },
                    )
                ],
            )
        )
        _reconcile_core_lifecycle_best_effort(str(failed.input.get("engagementId") or failed.target_id), repo, "core_teardown_failed")
        return failed.to_detail()

    if prior_cleanup:
        job = _append_pilot_job_event(
            repo, job, "info", "core Terraform cleanup skipped from durable prior proof",
            {"sourceAttemptSequence": prior_cleanup["attemptSequence"], "sourceResultSequence": prior_cleanup["resultSequence"]},
        )
        result_body = {
            "ok": True, "workspace": PILOT_WORKSPACE_NAME,
            "workspaceDir": str(workspace_dir), "mutationStatus": "destroyed",
            "ansibleStatus": "not_started", "finalCleanupStatus": "verified_clean",
            "deploymentMode": DESTROY_AFTER_VALIDATION,
        }
    else:
        result_body = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    inspector_validation: dict[str, Any] | None = None
    inspector_cleanup: dict[str, Any] | None = None
    if result_body.get("finalCleanupStatus") == "verified_clean":
        inspector_validation = _verify_retired_public_endpoints_before_inspector_cleanup(repo, job)
        job = repo.get(job.id) or job
        result_body["inspectorTeardownVerification"] = inspector_validation
        if inspector_validation.get("ok") is True:
            inspector_cleanup = _cleanup_inspector_after_core_teardown(repo, job)
            job = repo.get(job.id) or job
            result_body["inspectorCleanup"] = inspector_cleanup
    inspector_validation_ok = inspector_validation is None or inspector_validation.get("ok") is True
    inspector_cleanup_ok = inspector_cleanup is None or inspector_cleanup.get("ok") is True
    final_status = (
        "succeeded"
        if result_body.get("finalCleanupStatus") == "verified_clean" and inspector_validation_ok and inspector_cleanup_ok
        else "failed"
    )
    final_events = _dedupe_job_events(
        job.events,
        _pilot_result_events(result_body, _next_sequence(job.events), include_guardrail_event=False),
    )
    final_events.append(
        JobEvent(
            _next_sequence(job.events + final_events),
            "info" if final_status == "succeeded" else "error",
            "pilot Standard RTI teardown finished",
            {
                "ok": final_status == "succeeded",
                "workspace": result_body.get("workspace") or PILOT_WORKSPACE_NAME,
                "workspaceDir": str(workspace_dir),
                "mutationStatus": result_body.get("mutationStatus"),
                "ansibleStatus": result_body.get("ansibleStatus"),
                "finalCleanupStatus": result_body.get("finalCleanupStatus"),
                "coreCleanupStatus": result_body.get("finalCleanupStatus"),
                "inspectorTeardownVerification": inspector_validation or {},
                "inspectorCleanup": inspector_cleanup or {},
                "verificationTargetSha256": teardown_target_sha256(_retired_public_endpoint_targets(job)),
                "deploymentMode": result_body.get("deploymentMode"),
                "timing": _timing_from(teardown_started),
            },
        )
    )
    saved = repo.save(
        replace(
            job,
            status=final_status,
            finished_at=_now(),
            events=job.events + final_events,
        )
    )
    _reconcile_core_lifecycle_best_effort(str(saved.input.get("engagementId") or saved.target_id), repo, "core_teardown_finished")
    return saved.to_detail()


def _prior_verified_core_cleanup(job: StoredJobRun, workspace_dir: Path) -> dict[str, int] | None:
    starts = [index for index, event in enumerate(job.events) if event.message == "operator teardown requested"]
    for position in range(len(starts) - 1, -1, -1):
        start = starts[position]
        end = starts[position + 1] if position + 1 < len(starts) else len(job.events)
        attempt = job.events[start:end]
        request = attempt[0]
        if str(request.data.get("workspaceDir") or "") != str(workspace_dir):
            continue
        cleanups = [event for event in attempt if event.message == "cleanup verification completed"]
        terminals = [event for event in attempt if event.message == "pilot Standard RTI teardown finished"]
        if len(cleanups) != 1 or len(terminals) != 1:
            continue
        cleanup, terminal = cleanups[0], terminals[0]
        if cleanup.data.get("status") == "verified_clean" and cleanup.data.get("ok") is True \
                and type(cleanup.data.get("remainingCount")) is int and cleanup.data.get("remainingCount") == 0 \
                and terminal.data.get("mutationStatus") == "destroyed" \
                and terminal.data.get("finalCleanupStatus") == "verified_clean" \
                and terminal.data.get("coreCleanupStatus") == "verified_clean" \
                and cleanup.sequence < terminal.sequence \
                and str(terminal.data.get("workspaceDir") or "") == str(workspace_dir):
            return {"attemptSequence": request.sequence, "resultSequence": terminal.sequence}
    return None


def _reconcile_core_lifecycle_best_effort(engagement_id: str, repository: JobRepository, reason: str) -> None:
    """Persist lifecycle alongside runtime core mutations without risking the job result."""

    if not engagement_id or not isinstance(repository, SqlAlchemyJobRepository):
        return
    try:
        from app.storage.engagement_repository import SqlAlchemyEngagementRepository
        from app.services.engagement_lifecycle import reconcile_engagement_lifecycle

        engagement = SqlAlchemyEngagementRepository().get(engagement_id)
        if engagement is not None:
            reconcile_engagement_lifecycle(
                engagement_id,
                administrative_status=engagement.status,
                job_repository=repository,
                reason=reason,
            )
    except Exception:
        # The job remains authoritative evidence and the synchronous reconcile
        # endpoint can repair the projection. A projection write must never turn
        # successful infrastructure cleanup into a failed mutation.
        return


def _teardown_terraform_state_path(
    job: StoredJobRun,
    *,
    workspace_dir: Path,
    engagement_workspace_root: Path,
    terraform_state_root: Path,
) -> Path:
    """Resolve state for both durable and pre-durable Barragan core jobs."""

    if str(job.input.get("terraformStatePolicy") or "").strip() == "private-local-state-v1":
        return core_deployment_state_path(
            str(job.input.get("engagementId") or ""),
            root=engagement_workspace_root,
            state_root=terraform_state_root,
        )
    return workspace_dir / "terraform.tfstate"


def _verify_retired_public_endpoints_before_inspector_cleanup(
    repository: JobRepository,
    job: StoredJobRun,
) -> dict[str, Any]:
    engagement_id = str(job.input.get("engagementId") or "").strip()
    engagement_name = str(job.input.get("engagementName") or "").strip() or engagement_id
    if not engagement_id:
        return {
            "ok": True,
            "status": "skipped_no_engagement",
            "targetCount": 0,
            "targets": [],
            "evidence": {},
        }
    targets = _retired_public_endpoint_targets(job)
    current = _append_pilot_job_event(
        repository,
        job,
        "info",
        "Inspector teardown verification requested",
        {"engagementId": engagement_id, "engagementName": engagement_name, "targets": targets, "targetCount": len(targets)},
    )
    try:
        result = verify_retired_public_endpoints_for_teardown(
            engagement_id,
            engagement_name,
            job.id,
            targets,
        )
    except Exception as exc:
        result = {
            "ok": False,
            "status": "verification_failed",
            "targetCount": len(targets),
            "targets": targets,
            "evidence": {},
            "errors": [_redacted_exception_message(exc, job.input)],
        }
    if _should_skip_core_only_teardown_inspector_unavailable(result, targets):
        result = {
            "ok": True,
            "status": "skipped_no_retained_inspector_core_only",
            "targetCount": len(targets),
            "targets": targets,
            "evidence": {},
            "note": (
                "OCI cleanup verification already confirmed core infrastructure removal; "
                "no retained Inspector host was available for the additional core "
                "public-management endpoint check."
            ),
        }
    _append_pilot_job_event(
        repository,
        current,
        "info" if result.get("ok") is True else "error",
        "Inspector teardown verification completed" if result.get("ok") is True else "Inspector teardown verification failed",
        result,
    )
    return result


def _should_skip_core_only_teardown_inspector_unavailable(result: dict[str, Any], targets: list[dict[str, Any]]) -> bool:
    if result.get("status") != "inspector_unavailable":
        return False
    if not targets:
        return False
    return all(target.get("targetGroup") == "core-public-management" for target in targets)


def _cleanup_inspector_after_core_teardown(
    repository: JobRepository,
    job: StoredJobRun,
) -> dict[str, Any]:
    engagement_id = str(job.input.get("engagementId") or "").strip()
    engagement_name = str(job.input.get("engagementName") or "").strip() or engagement_id
    if not engagement_id:
        return {
            "ok": True,
            "status": "skipped_no_engagement",
            "disabled": False,
            "cleanupVerified": True,
            "currentHostCleared": False,
            "inspectorHost": {},
        }
    current = _append_pilot_job_event(
        repository,
        job,
        "info",
        "Inspector cleanup requested",
        {"engagementId": engagement_id, "engagementName": engagement_name},
    )
    try:
        cleanup = cleanup_inspector_for_infrastructure_teardown(
            engagement_id,
            engagement_name,
            job.id,
        )
    except Exception as exc:
        cleanup = {
            "ok": False,
            "status": "cleanup_required",
            "disabled": False,
            "cleanupVerified": False,
            "currentHostCleared": False,
            "inspectorHost": {},
            "errors": [_redacted_exception_message(exc, job.input)],
        }
    _append_pilot_job_event(
        repository,
        current,
        "info" if cleanup.get("ok") is True else "error",
        "Inspector cleanup completed" if cleanup.get("ok") is True else "Inspector cleanup failed",
        cleanup,
    )
    return cleanup


def _retired_public_endpoint_targets(job: StoredJobRun) -> list[dict[str, Any]]:
    explicit = job.input.get("engagementTeardownVerificationTargets")
    if isinstance(explicit, list):
        return [dict(target) for target in explicit if isinstance(target, dict)]
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | str]] = set()

    def add_target(target: dict[str, Any]) -> None:
        host = str(target.get("host") or "").strip()
        port = target.get("port", "")
        target_type = str(target.get("type") or "").strip()
        if not host or not target_type:
            return
        key = (target_type, host.lower(), port if isinstance(port, int) else str(port))
        if key in seen:
            return
        seen.add(key)
        targets.append(target)

    channel_rows: list[dict[str, Any]] = []
    connection_rows: list[dict[str, Any]] = []
    for event in job.events:
        if isinstance(event.data.get("inboundChannels"), list):
            channel_rows = [row for row in event.data["inboundChannels"] if isinstance(row, dict)]
        if isinstance(event.data.get("connectionDetails"), list):
            connection_rows = [row for row in event.data["connectionDetails"] if isinstance(row, dict)]

    for channel in channel_rows:
        port = _port_value(channel.get("externalPort") or channel.get("port"))
        host = str(
            channel.get("edgePublicIp")
            or channel.get("publicIp")
            or channel.get("connectHost")
            or channel.get("host")
            or ""
        ).strip()
        if host and port is not None:
            add_target(
                {
                    "id": str(channel.get("channelId") or f"{host}:{port}"),
                    "type": "tcp-forbidden",
                    "host": host,
                    "port": port,
                    "edge": str(channel.get("edge") or ""),
                    "protocol": str(channel.get("protocol") or "TCP").upper(),
                    "purpose": str(channel.get("purpose") or ""),
                    "service": str(channel.get("service") or ""),
                }
            )
        domain = str(channel.get("domain") or "").strip()
        expected_ip = str(channel.get("edgePublicIp") or channel.get("publicIp") or "").strip()
        if _looks_like_public_dns_name(domain):
            target = {
                "id": f"dns:{domain}",
                "type": "dns-absent",
                "host": domain,
                "channelId": str(channel.get("channelId") or ""),
            }
            if expected_ip:
                target["expectedIp"] = expected_ip
            add_target(target)

    for row in connection_rows:
        public_ip = str(row.get("publicIp") or "").strip()
        role = str(row.get("role") or "").strip()
        if public_ip and role in {"homebase", "proxy"}:
            add_target(
                {
                    "id": f"core-management:{row.get('displayName') or public_ip}:22",
                    "type": "tcp-forbidden",
                    "host": public_ip,
                    "port": 22,
                    "targetGroup": "core-public-management",
                    "service": "SSH",
                }
            )
    return targets


def _port_value(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _looks_like_public_dns_name(value: str) -> bool:
    if not value or value in {"N/A", "Not Deployed"} or "*" in value:
        return False
    return "." in value and not re.fullmatch(r"[0-9.]+", value)


def _workspace_dir(value: Any) -> Path:
    if isinstance(value, str) and value.strip():
        return Path(value)
    return Path(tempfile.mkdtemp(prefix="barragan-disposable-"))


def _validate_guarded_pilot_request(
    body: Mapping[str, Any],
    engagement: Any,
    target: OciDeploymentTarget,
) -> None:
    expected_confirmation = _deployment_confirmation_token(engagement.name, target)
    if body.get("confirmMutation") != expected_confirmation:
        raise GuardedDeploymentConfirmationError(
            f'confirmMutation must equal "{expected_confirmation}"'
        )
    if (
        _request_deployment_mode(body) == DESTROY_AFTER_VALIDATION
        and body.get(CLEANUP_ACKNOWLEDGEMENT_LABEL) is not True
    ):
        raise GuardedDeploymentConfirmationError(
            f"{CLEANUP_ACKNOWLEDGEMENT_LABEL} must be true"
        )
    cidrs = _request_ssh_source_cidrs(body)
    if not cidrs:
        raise GuardedDeploymentConfirmationError("sshSourceCidrs must include at least one trusted CIDR")
    if any(cidr == "0.0.0.0/0" for cidr in cidrs):
        raise GuardedDeploymentConfirmationError("sshSourceCidrs must not include 0.0.0.0/0")
    if not str(body.get("engagementId") or "").strip():
        raise GuardedDeploymentConfirmationError("engagementId is required for Standard RTI deployment naming")


def _validate_core_recreate_guard(
    body: Mapping[str, Any],
    engagement_name: str,
    engagement_id: str,
    repository: JobRepository,
) -> None:
    active_job = _active_core_job_for_engagement(engagement_id, repository)
    if active_job is None:
        return
    token = _core_recreate_confirmation_token(engagement_name)
    if body.get(CORE_RECREATE_FLAG) is True and str(body.get(CORE_RECREATE_CONFIRMATION_LABEL) or "") == token:
        return
    raise GuardedDeploymentConfirmationError(
        "active core infrastructure already exists; use the running infrastructure workflow "
        f'or confirm core recreation with {CORE_RECREATE_CONFIRMATION_LABEL}="{token}"'
    )


def _active_core_job_for_engagement(engagement_id: str, repository: JobRepository) -> StoredJobRun | None:
    for job in repository.list():
        if job.action != PILOT_JOB_ACTION or str(job.input.get("engagementId") or "") != engagement_id:
            continue
        if job.status in {"queued", "running"}:
            return job
        final_cleanup_status = _latest_event_value(job.events, "finalCleanupStatus")
        mutation_status = _latest_event_value(job.events, "mutationStatus")
        if final_cleanup_status == "pending_operator_teardown":
            return job
        if job.status == "succeeded" and mutation_status == "deployed" and final_cleanup_status != "verified_clean":
            return job
    return None


def _core_recreate_confirmation_token(engagement_name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", engagement_name.strip().lower())
    slug = re.sub(r"-+", "-", slug).strip("-")
    return f"recreate-core-{slug or 'engagement'}"


def _new_pilot_job(
    body: Mapping[str, Any],
    workspace_dir: Path,
    engagement_name: str,
    proxy_count: int,
    target: OciDeploymentTarget,
) -> StoredJobRun:
    created_at = _now()
    ssh_source_cidrs = _request_ssh_source_cidrs(body)
    names = pilot_names(engagement_name)
    safe_input = {
        "confirmMutation": body.get("confirmMutation"),
        CLEANUP_ACKNOWLEDGEMENT_LABEL: body.get(CLEANUP_ACKNOWLEDGEMENT_LABEL) is True,
        "deploymentMode": _request_deployment_mode(body),
        "engagementId": str(body.get("engagementId") or "").strip() or None,
        "engagementName": engagement_name,
        "proxyCount": proxy_count,
        "templateId": str(body.get("templateId") or "standard-rti"),
        "elkEnabled": body.get("elkEnabled") is True,
        "computeProfileSnapshot": dict(body.get("computeProfileSnapshot") or {}) if isinstance(body.get("computeProfileSnapshot"), Mapping) else {},
        **({"providerKeyedSourcePin": dict(body["providerKeyedSourcePin"])}
           if isinstance(body.get("providerKeyedSourcePin"), Mapping) else {}),
        **({"corePlanEvidenceSha256": body["corePlanEvidenceSha256"]}
           if isinstance(body.get("corePlanEvidenceSha256"), str) else {}),
        "resourceNames": {
            "homebase": names.homebase_name,
            "proxy01": names.proxy_name,
            **({"proxy02": names.proxy02_name} if proxy_count == 2 else {}),
            "vcn": names.vcn_name,
        },
        "sshSourceCidrs": ssh_source_cidrs,
        "sshSourceCidr": ssh_source_cidrs[0] if ssh_source_cidrs else None,
        "workspace": PILOT_WORKSPACE_NAME,
        "workspaceDir": str(workspace_dir),
        "terraformStatePolicy": "private-local-state-v1",
        "terraformStateLocator": body.get("terraformStateLocator"),
        "pendingSketchChainIds": [
            str(value)
            for value in body.get("pendingSketchChainIds", [])
            if str(value).strip()
        ],
        "pendingSketchChainFingerprints": {
            str(key): str(value)
            for key, value in body.get("pendingSketchChainFingerprints", {}).items()
            if str(key).strip() and str(value).strip()
        } if isinstance(body.get("pendingSketchChainFingerprints"), Mapping) else {},
        "sketchStateSchema": str(body.get("sketchStateSchema") or "split-v1"),
        "corePlanId": str(body.get("corePlanId") or "") or None,
        CORE_RECREATE_FLAG: body.get(CORE_RECREATE_FLAG) is True,
        "target": {
            "name": target.name,
            "compartmentId": target.compartment_id,
            "region": target.region,
            "auth": target.auth,
        },
    }
    return StoredJobRun(
        id=f"job-{uuid4().hex[:12]}",
        action=PILOT_JOB_ACTION,
        status="queued",
        target=f"oci-compartment:{target.name}",
        target_type="oci_compartment",
        target_id=target.compartment_id,
        requested_by=str(body.get("requestedBy") or "operator"),
        input=safe_input,
        artifact_refs=[],
        created_at=created_at,
        started_at=None,
        finished_at=None,
        events=[
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run queued",
                {
                    "workspace": PILOT_WORKSPACE_NAME,
                    "workspaceDir": str(workspace_dir),
                    "target": target.name,
                    "region": target.region,
                },
            )
        ],
    )


def _start_background_task(task: Callable[[], None]) -> None:
    start_runtime_task(
        task,
        name="barragan-pilot-standard-rti-runner",
    )


def _append_pilot_job_event(
    repository: JobRepository,
    job: StoredJobRun,
    level: str,
    message: str,
    data: dict[str, Any],
) -> StoredJobRun:
    current = repository.get(job.id) or job
    return repository.save(
        replace(
            current,
            events=current.events
            + [JobEvent(_next_sequence(current.events), level, message, data)],
        )
    )


def _job_detail_with_connection_details(job: StoredJobRun) -> JobRunDetail:
    job = _job_with_recovered_teardown_status(job)
    if _latest_event_value(job.events, "finalCleanupStatus") != "pending_operator_teardown":
        return job.to_detail()
    if any(isinstance(event.data.get("connectionDetails"), list) and event.data["connectionDetails"] for event in job.events):
        return job.to_detail()
    details = _connection_details_from_workspace(job)
    if not details:
        return job.to_detail()
    enriched = replace(
        job,
        events=job.events
        + [
            JobEvent(
                _next_sequence(job.events),
                "info",
                "operator connection details recovered",
                {
                    "status": "deployed",
                    "workspace": PILOT_WORKSPACE_NAME,
                    "workspaceDir": str(job.input.get("workspaceDir") or ""),
                    "connectionDetails": details,
                },
            )
        ],
    )
    return enriched.to_detail()


def _job_with_recovered_teardown_status(job: StoredJobRun) -> StoredJobRun:
    if job.status in {"queued", "running"}:
        return job
    if _latest_event_value(job.events, "finalCleanupStatus") == "verified_clean":
        return job
    cleanup_event = next(
        (
            event
            for event in reversed(job.events)
            if event.message == "cleanup verification completed" and event.data.get("status") == "verified_clean"
        ),
        None,
    )
    if cleanup_event is None:
        return job
    return replace(
        job,
        events=job.events
        + [
            JobEvent(
                _next_sequence(job.events),
                "info",
                "pilot Standard RTI teardown finished",
                {
                    "ok": cleanup_event.data.get("ok"),
                    "workspace": PILOT_WORKSPACE_NAME,
                    "workspaceDir": str(job.input.get("workspaceDir") or ""),
                    "mutationStatus": "destroyed",
                    "ansibleStatus": "not_started",
                    "finalCleanupStatus": "verified_clean",
                    "deploymentMode": DESTROY_AFTER_VALIDATION,
                },
            )
        ],
    )


def _latest_event_value(events: list[JobEvent], key: str) -> Any:
    event = next((entry for entry in reversed(events) if entry.data.get(key) is not None), None)
    return event.data.get(key) if event is not None else None


def _connection_details_from_workspace(job: StoredJobRun) -> list[dict[str, Any]]:
    workspace_dir = job.input.get("workspaceDir")
    workspace = Path(str(workspace_dir or ""))
    if not str(workspace_dir or "").strip():
        return []
    inventory_path = workspace / "ansible" / "runtime_inventory.ini"
    if not inventory_path.exists():
        return []
    content = inventory_path.read_text(encoding="utf-8")
    homebase = _inventory_host_value(content, "homebase", "ansible_host")
    proxy01 = _inventory_host_value(content, "proxy01", "ansible_host")
    proxy_count = _proxy_count_from_value(job.input.get("proxyCount"))
    proxy02 = _inventory_host_value(content, "proxy02", "ansible_host") if proxy_count == 2 else None
    if not homebase or not proxy01 or (proxy_count == 2 and not proxy02):
        return []
    names = pilot_names(str(job.input.get("engagementName") or "pilot"))
    region = _job_target_region(job)
    return [
        {
            "role": "homebase",
            "displayName": names.homebase_name,
            "sshAlias": names.homebase_name,
            "publicIp": homebase,
            "privateIp": PILOT_HOMEBASE_PRIVATE_IP,
            "region": region,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh {names.homebase_name}",
            "services": ["SSH", "RTI base layout", "proxy config banks", "dropbox NFS export"],
        },
        {
            "role": "proxy",
            "displayName": names.proxy_name,
            "sshAlias": names.proxy_name,
            "publicIp": proxy01,
            "privateIp": PILOT_PROXY_PRIVATE_IP,
            "region": region,
            "sshUser": CORE_MANAGEMENT_SSH_USER,
            "sshCommand": f"ssh {names.proxy_name}",
            "services": ["SSH", "RTI base layout", "dropbox NFS mount", "nmap"],
        },
        *(
            [
                {
                    "role": "proxy",
                    "displayName": names.proxy02_name,
                    "sshAlias": names.proxy02_name,
                    "publicIp": proxy02,
                    "privateIp": PILOT_PROXY02_PRIVATE_IP,
                    "region": region,
                    "sshUser": CORE_MANAGEMENT_SSH_USER,
                    "sshCommand": f"ssh {names.proxy02_name}",
                    "services": ["SSH", "RTI base layout", "dropbox NFS mount", "nmap"],
                }
            ]
            if proxy_count == 2 and proxy02
            else []
        ),
    ]


def _job_target_region(job: StoredJobRun) -> str:
    target = job.input.get("target")
    if isinstance(target, dict):
        return str(target.get("region") or "")
    return ""


def _required_engagement(body: Mapping[str, Any]) -> Any:
    engagement_id = str(body.get("engagementId") or "").strip()
    if not engagement_id:
        raise GuardedDeploymentConfirmationError("engagementId is required for Standard RTI deployment naming")
    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise GuardedDeploymentConfirmationError(f"engagementId {engagement_id} was not found")
    return engagement


def _proxy_count_for_optional_engagement_id(engagement_id: str | None) -> int:
    resolved_id = str(engagement_id or "").strip()
    if not resolved_id:
        return 2
    engagement = get_engagement(resolved_id)
    if engagement is None:
        return 2
    return _proxy_count_for_engagement(engagement)


def _proxy_count_for_engagement(engagement: Any) -> int:
    input_parameters = getattr(engagement, "input_parameters", {}) or {}
    explicit = input_parameters.get("proxyCount") if isinstance(input_parameters, Mapping) else None
    if explicit is not None:
        return _proxy_count_from_value(explicit)
    from app.services.catalog import is_single_proxy_template

    return 1 if is_single_proxy_template(str(getattr(engagement, "template_id", ""))) else 2


def _proxy_count_from_value(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = 2
    return 1 if parsed == 1 else 2


def _engagement_name_for_optional_id(engagement_id: str | None) -> str:
    resolved_id = str(engagement_id or "").strip()
    if not resolved_id:
        return "pilot"
    engagement = get_engagement(resolved_id)
    if engagement is None:
        return "pilot"
    return engagement.name


def _engagement_for_optional_id(engagement_id: str | None) -> Any | None:
    resolved_id = str(engagement_id or "").strip()
    return get_engagement(resolved_id) if resolved_id else None


def _runtime_environment() -> str:
    try:
        return str(runtime_value("ENVIRONMENT", "local") or "local")
    except RuntimeError:
        return "local"


def _target_for_engagement(engagement: Any | None) -> OciDeploymentTarget:
    parameters = getattr(engagement, "input_parameters", {}) if engagement is not None else {}
    value = parameters.get("deploymentTarget") if isinstance(parameters, Mapping) else None
    try:
        return resolve_oci_deployment_target(value, environment=_runtime_environment())
    except OciDeploymentTargetError as exc:
        raise GuardedDeploymentConfirmationError(str(exc)) from exc


def _deployment_confirmation_token(engagement_name: str, target: OciDeploymentTarget) -> str:
    if target == BARRAGAN_TESTING_TARGET:
        return EXECUTION_CONFIRMATION
    engagement_slug = re.sub(r"[^a-z0-9-]+", "-", engagement_name.strip().lower())
    target_slug = re.sub(r"[^a-z0-9-]+", "-", target.name.strip().lower())
    return f"deploy-{engagement_slug or 'engagement'}-to-{target_slug}"


def _inventory_host_value(content: str, host: str, key: str) -> str | None:
    for line in content.splitlines():
        parts = line.split()
        if not parts or parts[0] != host:
            continue
        prefix = f"{key}="
        for part in parts[1:]:
            if part.startswith(prefix):
                return part.removeprefix(prefix)
    return None


def _redacted_exception_message(exc: Exception, body: Mapping[str, Any]) -> str:
    message = str(exc) or type(exc).__name__
    for value in _sensitive_ssh_key_paths(body):
        message = message.replace(value, "[redacted SSH key path]")
    message = re.sub(
        r"(?i)(--private-key(?:=|\s+))[^,\s'\"\]\)]+",
        r"\1[redacted SSH key path]",
        message,
    )
    message = re.sub(
        r"(?i)(ansible_(?:ssh_)?private_key_file=)[^,\s'\"\]\)]+",
        r"\1[redacted SSH key path]",
        message,
    )
    message = re.sub(
        r"(?i)(\s-i\s+)[^,\s'\"\]\)]+",
        r"\1[redacted SSH key path]",
        message,
    )
    message = re.sub(
        r"(?i)(?:~|/)[^,\s'\"\]\)]*(?:\.ssh/|/id_(?:rsa|dsa|ecdsa|ed25519)|(?:ssh|key|pem|rsa|ed25519)[^/,\s'\"\]\)]*)",
        "[redacted SSH key path]",
        message,
    )
    return message


def _sensitive_ssh_key_paths(body: Mapping[str, Any]) -> list[str]:
    values = [
        body.get("sshPrivateKeyPath"),
        body.get("sshPublicKeyPath"),
        os.environ.get(SSH_PRIVATE_KEY_ENV),
        os.environ.get(SSH_PUBLIC_KEY_ENV),
    ]
    paths = []
    for value in values:
        if value is None:
            continue
        path = str(value).strip()
        if path:
            paths.append(path)
    return sorted(set(paths), key=len, reverse=True)


def _pilot_result_events(
    result: Mapping[str, Any],
    first_sequence: int,
    *,
    include_guardrail_event: bool = True,
    include_preflight_event: bool = True,
    include_command_events: bool = True,
    include_operator_inspection_ready: bool = True,
    include_finished: bool = True,
) -> list[JobEvent]:
    workspace = str(result.get("workspace") or PILOT_WORKSPACE_NAME)
    workspace_dir = str(result.get("workspaceDir") or "")
    commands_run = list(result.get("commandsRun") or [])
    cleanup = result.get("cleanupVerification") if isinstance(result.get("cleanupVerification"), Mapping) else None
    channel_rows = _deployment_channel_rows(result)
    events = []
    if include_guardrail_event:
        events.append(
            ("info", "readiness and guardrails accepted", {"workspace": workspace, "workspaceDir": workspace_dir})
        )
    if include_preflight_event:
        events.append(
            (
                "info" if _preflight_ok(result) else "error",
                "OCI read preflight completed",
                {"ok": _preflight_ok(result), "mutationStatus": result.get("mutationStatus")},
            )
        )
    if result.get("mutationStatus") == "ssh_key_unresolved":
        events.append(
            (
                "error",
                "SSH validation key configuration unresolved",
                {"status": "failed", "workspace": workspace, "workspaceDir": workspace_dir},
            )
        )
    if include_command_events:
        events += _command_events(
            commands_run,
            include_teardown=result.get("finalCleanupStatus") != "pending_operator_teardown",
        )
    if result.get("finalCleanupStatus") == "pending_operator_teardown" and include_operator_inspection_ready:
        events.append(
            (
                "info",
                "operator inspection ready",
                {
                    "status": "deployed",
                    "workspace": workspace,
                    "workspaceDir": workspace_dir,
                    "connectionDetails": list(result.get("connectionDetails") or []),
                    "outboundChannels": channel_rows["outboundChannels"],
                    "inboundChannels": channel_rows["inboundChannels"],
                },
            )
        )
    elif result.get("finalCleanupStatus") != "pending_operator_teardown":
        events.append(
            (
                "info" if result.get("finalCleanupStatus") == "verified_clean" else "error",
                "cleanup verification completed",
                {
                    "status": result.get("finalCleanupStatus"),
                    "ok": cleanup.get("ok") if cleanup else None,
                    "remainingCount": cleanup.get("remainingCount") if cleanup else None,
                },
            )
        )
    if include_finished:
        events.append(
            (
                "info" if result.get("ok") is True else "error",
                "pilot Standard RTI run finished",
                {
                    "ok": result.get("ok"),
                    "workspace": workspace,
                    "workspaceDir": workspace_dir,
                    "mutationStatus": result.get("mutationStatus"),
                    "ansibleStatus": result.get("ansibleStatus"),
                    "finalCleanupStatus": result.get("finalCleanupStatus"),
                    "deploymentMode": result.get("deploymentMode"),
                    "connectionDetails": list(result.get("connectionDetails") or []),
                    "outboundChannels": channel_rows["outboundChannels"],
                    "inboundChannels": channel_rows["inboundChannels"],
                },
            )
        )
    return [
        JobEvent(first_sequence + index, level, message, data)
        for index, (level, message, data) in enumerate(events)
    ]


def _deployment_channel_rows(result: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if result.get("ansibleStatus") != "validated" or result.get("mutationStatus") not in {
        "deployed",
        "destroyed",
        "destroy_failed",
    }:
        return {"outboundChannels": [], "inboundChannels": []}
    return {
        "outboundChannels": [
            row for row in list(result.get("outboundChannels") or []) if isinstance(row, dict)
        ],
        "inboundChannels": [
            row for row in list(result.get("inboundChannels") or []) if isinstance(row, dict)
        ],
    }


def _dedupe_job_events(existing: list[JobEvent], candidates: list[JobEvent]) -> list[JobEvent]:
    existing_messages = {event.message for event in existing}
    filtered = [event for event in candidates if event.message not in existing_messages]
    first_sequence = _next_sequence(existing)
    return [
        JobEvent(first_sequence + index, event.level, event.message, event.data)
        for index, event in enumerate(filtered)
    ]


def _preflight_ok(result: Mapping[str, Any]) -> bool:
    preflight = result.get("preflight")
    if isinstance(preflight, Mapping):
        return preflight.get("ok") is True
    return result.get("mutationStatus") != "preflight_failed"


def _command_events(commands_run: list[Any], *, include_teardown: bool = True) -> list[tuple[str, str, dict[str, Any]]]:
    step_specs = [
        ("terraform_init", "Terraform init completed", _command_matches("init")),
        ("terraform_apply", "Terraform apply completed", _command_matches("apply")),
        ("terraform_output", "Terraform output completed", _command_matches("output")),
        ("ssh_readiness", "SSH readiness validation completed", _command_matches("wait_for_connection")),
        ("ansible_ping", "Ansible ping validation completed", _command_matches("ping")),
        ("ansible_bootstrap", "Ansible bootstrap validation completed", _command_matches("bootstrap_validate")),
        ("ansible_capabilities", "Ansible selected capabilities apply completed", _command_matches("apply_capabilities")),
    ]
    if include_teardown:
        step_specs.append(("terraform_destroy", "Terraform destroy completed", _command_matches("destroy")))
    events: list[tuple[str, str, dict[str, Any]]] = []
    for step, message, matcher in step_specs:
        command = next((entry for entry in commands_run if isinstance(entry, Mapping) and matcher(entry)), None)
        if command is None:
            events.append(("warning", message, {"step": step, "status": "not_recorded"}))
            continue
        ok = command.get("ok") is True
        events.append(
            (
                "info" if ok else "error",
                message,
                {
                    "step": step,
                    "status": "succeeded" if ok else "failed",
                    "returncode": command.get("returncode"),
                    "cwd": command.get("cwd"),
                },
            )
        )
    return events


def _command_matches(needle: str) -> Callable[[Mapping[str, Any]], bool]:
    def matches(entry: Mapping[str, Any]) -> bool:
        command = entry.get("command")
        return isinstance(command, list) and any(needle in str(part) for part in command)

    return matches


def _sanitize_core_plan_event_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """Remove controller-local evidence before persisting exact-plan events."""
    private_keys = {"workspaceDir", "cwd", "commandOutputArtifactRefs", "path", "planPath", "terraformDataDir", "terraformStatePath"}
    return {
        str(key): value
        for key, value in data.items()
        if str(key) not in private_keys
    }


def _sanitize_core_plan_job_detail(detail: JobRunDetail) -> JobRunDetail:
    safe_input = {
        key: value
        for key, value in detail.input.items()
        if key not in {"workspaceDir", "sshPrivateKeyPath", "sshPublicKeyPath", "preparedCoreRun", "providerKeyedSourcePin", "corePlanEvidenceSha256", "providerKeyedDispatchAuthorized"}
    }
    return replace(
        detail,
        input=safe_input,
        artifact_refs=[],
        events=[replace(event, data=_sanitize_core_plan_event_data(event.data)) for event in detail.events],
    )


def _require_configured_keyed_source(expected: object = None) -> dict[str, str]:
    from app.services.provider_keyed_core_source import (
        ProviderKeyedCoreSourceError, require_keyed_core_source,
    )

    configured = str(runtime_value("PROVIDER_KEYED_TEMPLATE_ROOT", "") or "").strip()
    try:
        if not configured:
            raise ProviderKeyedCoreSourceError("pinned provider-keyed source is unavailable or changed")
        pin = require_keyed_core_source(Path(configured))
        if expected is not None and pin != expected:
            raise ProviderKeyedCoreSourceError("pinned provider-keyed source is unavailable or changed")
        return pin
    except ProviderKeyedCoreSourceError as exc:
        raise GuardedDeploymentConfirmationError(str(exc)) from None


def _release_core_mutation_lease(engagement_id: str, owner_id: str) -> None:
    if not engagement_id or not owner_id:
        return
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository

    SqlAlchemyDeploymentPlanRepository().release(engagement_id, owner_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timing_from(started_at: datetime) -> dict[str, Any]:
    finished_at = datetime.now(timezone.utc)
    return {
        "startedAt": started_at.isoformat(),
        "finishedAt": finished_at.isoformat(),
        "durationSeconds": round((finished_at - started_at).total_seconds(), 3),
    }


def _next_sequence(events: list[JobEvent]) -> int:
    return max((event.sequence for event in events), default=0) + 1


def _command_resolution_dict(resolution: CommandResolution) -> dict[str, Any]:
    return {
        "binaryName": resolution.binary_name,
        "command": resolution.command,
        "source": resolution.source,
        "overrideVariables": list(resolution.override_variables),
        "ok": resolution.ok,
        "error": resolution.error,
    }


def _configured(variable: str, env: Mapping[str, str] | None) -> bool:
    return bool(_env_value(variable, env))


def _env_value(variable: str, env: Mapping[str, str] | None) -> str | None:
    lookup = env if env is not None else os.environ
    value = lookup.get(variable, "").strip()
    return value or None


def _pilot_ssh_source_cidrs(env: Mapping[str, str] | None) -> list[str]:
    configured = _env_value(SSH_SOURCE_CIDRS_ENV, env)
    if configured:
        return _normalize_cidrs(configured.split(","))
    legacy_configured = _env_value(SSH_SOURCE_CIDR_ENV, env)
    if legacy_configured:
        return _normalize_cidrs([legacy_configured])
    return list(DEFAULT_OPERATOR_SSH_SOURCE_CIDRS)


def _request_ssh_source_cidrs(body: Mapping[str, Any]) -> list[str]:
    values = body.get("sshSourceCidrs")
    if isinstance(values, list):
        return _normalize_cidrs([str(value) for value in values])
    legacy_value = str(body.get("sshSourceCidr", "")).strip()
    if legacy_value:
        return _normalize_cidrs([legacy_value])
    return list(DEFAULT_OPERATOR_SSH_SOURCE_CIDRS)


def _normalize_cidrs(values: list[str]) -> list[str]:
    seen = set()
    cidrs = []
    for value in values:
        cidr = str(value).strip()
        if not cidr or cidr in seen:
            continue
        seen.add(cidr)
        cidrs.append(cidr)
    return cidrs


def _request_deployment_mode(body: Mapping[str, Any]) -> str:
    return DESTROY_AFTER_VALIDATION if body.get("deploymentMode") == DESTROY_AFTER_VALIDATION else HOLD_FOR_REVIEW
