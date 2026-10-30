# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.domain import JobEvent
from app.integrations.oci_read_validation import (
    CommandRunner,
    OciDevelopmentTarget,
    OciReadValidationResult,
    build_read_checks,
    run_read_validation,
)
from app.integrations.provider_plans import (
    build_provider_plan_bundle,
    render_ansible_intent,
    render_terraform_intent,
)
from app.integrations.pilot_standard_rti import build_pilot_standard_rti_workspace
from app.services.access_plans import PlatformAccessUser, plan_access_propagation
from app.services.git_renderer import render_revision_plan
from app.services.revision_compiler import compile_standard_rti_revision


@dataclass(frozen=True)
class PlanOnlyDeploymentResult:
    revision: dict[str, Any]
    provider_plan: dict[str, Any]
    provider_preflight: dict[str, Any]
    deploy_readiness: dict[str, Any]
    terraform_intent: dict[str, Any]
    ansible_intent: dict[str, Any]
    access_plan: dict[str, Any]
    render_result: dict[str, Any] | None
    terraform_files: list[dict[str, str]]
    events: list[JobEvent]

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision": self.revision,
            "providerPlan": self.provider_plan,
            "providerPreflight": self.provider_preflight,
            "deployReadiness": self.deploy_readiness,
            "terraformIntent": self.terraform_intent,
            "ansibleIntent": self.ansible_intent,
            "accessPlan": self.access_plan,
            "renderResult": self.render_result,
            "terraformFiles": self.terraform_files,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass(frozen=True)
class RequiredProviderPreflight:
    name: str
    provider: str
    required: bool
    status: str
    validation: dict[str, Any]

    @property
    def ok(self) -> bool:
        return self.status == "passed"

    @property
    def blocks_deploy_readiness(self) -> bool:
        return self.required and not self.ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "required": self.required,
            "status": self.status,
            "ok": self.ok,
            "mode": "read_only",
            "mutation": False,
            "blocksDeployReadiness": self.blocks_deploy_readiness,
            "validation": self.validation,
        }


def plan_standard_rti_deployment(
    engagement_id: str,
    input_parameters: dict[str, Any],
    access_users: list[PlatformAccessUser] | None = None,
    render_destination: Path | None = None,
    render_job_id: str = "job-plan-only-render",
    provider_preflight_result: OciReadValidationResult | None = None,
    provider_preflight_runner: CommandRunner | None = None,
    run_provider_preflight: bool = False,
) -> PlanOnlyDeploymentResult:
    events = [
        JobEvent(1, "info", "plan-only deployment started", {"engagementId": engagement_id}),
    ]

    revision = compile_standard_rti_revision(engagement_id, input_parameters)
    events.append(JobEvent(2, "info", "deployment revision compiled", {"revisionId": revision.id}))

    provider_plan = build_provider_plan_bundle(revision)
    events.append(JobEvent(3, "info", "provider dry-run plan built", {"mode": provider_plan.mode}))

    provider_preflight = _resolve_required_provider_preflight(
        provider_preflight_result=provider_preflight_result,
        provider_preflight_runner=provider_preflight_runner,
        run_provider_preflight=run_provider_preflight,
    )
    readiness = _build_deploy_readiness(provider_preflight)
    events.append(_provider_preflight_event(len(events) + 1, provider_preflight, readiness))

    terraform_intent = render_terraform_intent(provider_plan)
    ansible_intent = render_ansible_intent(revision, provider_plan)
    events.append(JobEvent(len(events) + 1, "info", "execution intent rendered", {"mutation": False}))

    access_plan = plan_access_propagation(revision, access_users or [])
    events.append(JobEvent(len(events) + 1, "info", "access propagation plan built", {"mode": access_plan.mode}))

    render_result = None
    if render_destination is not None:
        render_result_obj = render_revision_plan(revision, render_destination, render_job_id)
        render_result = render_result_obj.to_dict()
        events.append(
            JobEvent(
                len(events) + 1,
                "info",
                "local Git-visible artifacts rendered",
                {"artifactCount": len(render_result_obj.artifacts), "mutation": False},
            )
        )

    events.append(JobEvent(len(events) + 1, "info", "plan-only deployment completed", {"mutation": False}))

    return PlanOnlyDeploymentResult(
        revision=revision.to_dict(),
        provider_plan=provider_plan.to_dict(),
        provider_preflight=provider_preflight.to_dict(),
        deploy_readiness=readiness,
        terraform_intent=terraform_intent,
        ansible_intent=ansible_intent,
        access_plan=access_plan.to_dict(),
        render_result=render_result,
        terraform_files=_terraform_source_files(revision.to_dict()),
        events=events,
    )


def _terraform_source_files(revision: dict[str, Any]) -> list[dict[str, str]]:
    parameters = revision.get("inputParameters") if isinstance(revision.get("inputParameters"), dict) else {}
    workspace = build_pilot_standard_rti_workspace(
        engagement_name=str(parameters.get("engagementName") or revision.get("engagementId") or "plan-preview"),
        proxy_count=int(parameters.get("proxyCount") or 2),
    )
    return [
        {"path": artifact.path, "language": "hcl", "source": artifact.content}
        for artifact in workspace.artifacts
        if artifact.path in {"versions.tf", "variables.tf", "main.tf"}
    ]


def _resolve_required_provider_preflight(
    provider_preflight_result: OciReadValidationResult | None,
    provider_preflight_runner: CommandRunner | None,
    run_provider_preflight: bool,
) -> RequiredProviderPreflight:
    if provider_preflight_result is not None and (
        provider_preflight_runner is not None or run_provider_preflight
    ):
        raise ValueError("provide either a cached provider preflight result or a runner, not both")

    if provider_preflight_result is not None:
        return _provider_preflight_from_validation(provider_preflight_result)

    if provider_preflight_runner is not None or run_provider_preflight:
        return _provider_preflight_from_validation(run_read_validation(runner=provider_preflight_runner))

    return _provider_preflight_preview()


def _provider_preflight_from_validation(
    validation_result: OciReadValidationResult,
) -> RequiredProviderPreflight:
    validation_result.target.validate()
    status = "passed" if validation_result.ok else "failed"
    return RequiredProviderPreflight(
        name="oci-read-validation",
        provider="oci",
        required=True,
        status=status,
        validation=validation_result.to_dict(),
    )


def _provider_preflight_preview() -> RequiredProviderPreflight:
    target = OciDevelopmentTarget()
    checks = []
    for check in build_read_checks(target):
        body = check.to_dict()
        body.update({"ok": None, "count": None, "error": None, "executed": False})
        checks.append(body)

    return RequiredProviderPreflight(
        name="oci-read-validation",
        provider="oci",
        required=True,
        status="not_run",
        validation={
            "ok": False,
            "mode": "read_only",
            "mutation": False,
            "target": target.to_dict(),
            "checks": checks,
        },
    )


def _build_deploy_readiness(preflight: RequiredProviderPreflight) -> dict[str, Any]:
    blocked_by = []
    if preflight.blocks_deploy_readiness:
        blocked_by.append(
            {
                "id": preflight.name,
                "provider": preflight.provider,
                "status": preflight.status,
                "reason": "required OCI read-validation preflight has not passed",
            }
        )

    return {
        "ready": not blocked_by,
        "blockedBy": blocked_by,
        "mutation": False,
    }


def _provider_preflight_event(
    sequence: int,
    preflight: RequiredProviderPreflight,
    readiness: dict[str, Any],
) -> JobEvent:
    if preflight.status == "passed":
        level = "info"
        message = "required provider preflight passed"
    elif preflight.status == "failed":
        level = "error"
        message = "required provider preflight failed"
    else:
        level = "warning"
        message = "required provider preflight not run"

    return JobEvent(
        sequence,
        level,
        message,
        {
            "provider": preflight.provider,
            "preflight": preflight.name,
            "status": preflight.status,
            "deployReady": readiness["ready"],
            "mutation": False,
        },
    )
