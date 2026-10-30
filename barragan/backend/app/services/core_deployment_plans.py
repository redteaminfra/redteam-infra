# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import runtime_value, start_runtime_task
from app.domain.deployment_plan import DeploymentPlan
from app.integrations.ansible_disposable_validation import SSH_PRIVATE_KEY_ENV, SSH_PUBLIC_KEY_ENV
from app.integrations.oci_disposable_terraform import resolve_terraform
from app.integrations.oci_compute_profiles import resolve_oci_compute_profile
from app.integrations.pilot_standard_rti import (
    OCI_CORE_DHCP_DNS_SERVERS,
    OCI_CORE_INSTANCE_AGENT_POLICY,
    OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
    OCI_CORE_PROXY_SKIP_SOURCE_DEST_CHECK,
    render_pilot_standard_rti_workspace,
)
from app.services.engagement_workspaces import DEFAULT_TERRAFORM_STATE_ROOT, prepare_core_deployment_run
from app.services.managed_host_image_continuity import managed_host_image_profile_named
from app.services.provider_catalog import ProviderCatalogTransport
from app.services.engagements import get_engagement
from app.services.revisions import get_revision
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError,
    DeploymentPlanRepository,
    SqlAlchemyDeploymentPlanRepository,
)


CommandRunner = Callable[[list[str], Path, Mapping[str, str]], subprocess.CompletedProcess[str]]
BackgroundRunner = Callable[[Callable[[], None]], None]
PLAN_FILENAME = "core.tfplan"
SAFE_TERRAFORM_SOURCE_FILES = ("versions.tf", "variables.tf", "main.tf")
KEYED_DIGITALOCEAN_LOCK_SHA256 = "0e6a4207cca9db67bba23b918748e02c4d32c1c504e09bad54e5d37751d99736"
KEYED_LINODE_LOCK_SHA256 = "40e181997472ad02b0a68ef1b826c745f2d69c41426ab2a6d7000f9261399a49"
KEYED_LINODE_SOURCE_SHA256 = "d0f3292ede53e09766f2710df3bc040410eaad24edd5f2f0d14b0dc8cf65d7ef"
KEYED_CORE_TERRAFORM_INPUT_FILES = (
    "versions.tf", "variables.tf", "main.tf", "terraform.tfvars.json", ".terraform.lock.hcl",
)
KEYED_CORE_TERRAFORM_INPUT_SCHEMA = "keyed-core-terraform-inputs-v1"


class CoreDeploymentPlanError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("core deployment plan validation failed")
        self.errors = errors


def start_core_deployment_plan(
    engagement_id: str,
    body: Mapping[str, Any],
    *,
    repository: DeploymentPlanRepository | None = None,
    background_runner: BackgroundRunner | None = None,
    command_runner: CommandRunner | None = None,
    engagement_workspace_root: Path = Path("/opt/engagements"),
    terraform_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
) -> DeploymentPlan:
    from app.services.engagement_teardown import assert_core_creation_allowed

    assert_core_creation_allowed(engagement_id)
    engagement = get_engagement(engagement_id)
    if engagement is None:
        raise CoreDeploymentPlanError(["engagement not found"])
    revision_id = str(body.get("revisionId") or engagement.active_revision or "").strip()
    revision = get_revision(revision_id) if revision_id else None
    if revision is None or revision.get("engagementId") != engagement_id:
        raise CoreDeploymentPlanError(["revisionId must identify a revision for this engagement"])
    _assert_reviewable_sketch_schema(engagement, revision)
    cidrs = _safe_cidrs(body.get("sshSourceCidrs"))
    if not cidrs:
        raise CoreDeploymentPlanError(["sshSourceCidrs must include at least one trusted CIDR"])

    repo = repository or SqlAlchemyDeploymentPlanRepository()
    plan_id = f"dpl-{uuid4().hex}"
    repo.acquire(engagement_id, plan_id, "prepare")
    try:
        previous = repo.current(engagement_id)
        repo.invalidate_current(engagement_id)
        if previous is not None:
            _cleanup_unapplied_plan_artifacts(previous)
        plan = repo.save(DeploymentPlan(plan_id, engagement_id, revision_id, "preparing", "queued"))
    except Exception:
        repo.release(engagement_id, plan_id)
        raise

    runner = background_runner or _start_background
    runner(
        lambda: _prepare_core_deployment_plan(
            plan.id,
            cidrs,
            repository=repo,
            command_runner=command_runner,
            engagement_workspace_root=engagement_workspace_root,
            terraform_state_root=terraform_state_root,
        )
    )
    return repo.get(plan.id) or plan


def get_current_core_deployment_plan(
    engagement_id: str, *, repository: DeploymentPlanRepository | None = None
) -> DeploymentPlan | None:
    repo = repository or SqlAlchemyDeploymentPlanRepository()
    plan = repo.current(engagement_id)
    return _invalidate_if_configuration_changed(plan, repo)


def get_core_deployment_plan(
    engagement_id: str, plan_id: str, *, repository: DeploymentPlanRepository | None = None
) -> DeploymentPlan | None:
    repo = repository or SqlAlchemyDeploymentPlanRepository()
    plan = repo.get(plan_id)
    if plan is None or plan.engagement_id != engagement_id:
        return None
    return _invalidate_if_configuration_changed(plan, repo)


def begin_core_deployment_plan_apply(
    engagement_id: str,
    plan_id: str,
    body: Mapping[str, Any],
    *,
    repository: DeploymentPlanRepository | None = None,
    job_starter=None,
    engagement_workspace_root: Path = Path("/opt/engagements"),
    terraform_state_root: Path = DEFAULT_TERRAFORM_STATE_ROOT,
) -> tuple[DeploymentPlan, Any]:
    from app.services.guarded_test_deployment import start_guarded_pilot_standard_rti_run
    from app.services.engagement_teardown import assert_core_creation_allowed

    assert_core_creation_allowed(engagement_id)

    repo = repository or SqlAlchemyDeploymentPlanRepository()
    plan = get_core_deployment_plan(engagement_id, plan_id, repository=repo)
    if plan is None:
        raise CoreDeploymentPlanError(["deployment plan not found"])
    if plan.status == "no_changes":
        raise CoreDeploymentPlanError(["a no-change plan is reviewable but cannot be deployed"])
    if plan.status != "ready":
        raise DeploymentPlanConflictError(f"deployment plan is {plan.status} and cannot be applied")
    _verify_plan_evidence(plan)
    if plan.evidence.get("sketchStateSchema", "split-v1") == "provider-keyed-v2":
        raise CoreDeploymentPlanError(["provider-keyed-v2 core apply is unavailable until provider-scoped rollout and teardown are enabled"])
    repo.acquire(engagement_id, plan.id, "apply")
    applying = repo.save(replace(plan, status="applying", stage="terraform_apply"))
    starter = job_starter or start_guarded_pilot_standard_rti_run
    try:
        job = starter(
            {
                **dict(body),
                "engagementId": engagement_id,
                "sshSourceCidrs": list(plan.evidence.get("sshSourceCidrs") or []),
            },
            prepared_core_run=dict(plan.evidence),
            core_plan_id=plan.id,
            **({"core_plan_revision_id": plan.revision_id}
               if plan.evidence.get("sketchStateSchema") == "provider-keyed-v2" else {}),
            engagement_workspace_root=engagement_workspace_root,
            terraform_state_root=terraform_state_root,
        )
        current = repo.get(plan.id) or applying
        # A synchronous test runner or very fast worker may have already moved
        # the plan to applied/reconciliation_required. Never overwrite that
        # terminal status with the stale pre-launch `applying` instance.
        current = repo.save(replace(current, apply_job_id=job.id))
        return current, job
    except Exception:
        current = repo.get(plan.id)
        if (current is not None and current.evidence.get("sketchStateSchema") == "provider-keyed-v2"
                and current.apply_job_id):
            # The queued core job and plan binding committed together before
            # worker launch. Once bound, even a failed launch is an ambiguous
            # recovery boundary; do not reopen the plan or release its lease.
            mark_bound_keyed_core_start_attention(current.id, current.engagement_id, current.apply_job_id)
        else:
            repo.save(replace(applying, status="ready", stage="ready"))
            repo.release(engagement_id, plan.id)
        raise


def _begin_private_devtest_keyed_core_plan_apply(
    engagement_id: str, plan_id: str, *,
    background_runner: BackgroundRunner | None = None,
    cleanup_visibility_transport: ProviderCatalogTransport | None = None,
    region_catalog_transport: ProviderCatalogTransport | None = None,
) -> tuple[DeploymentPlan, Any]:
    """Start one reviewed keyed core worker without opening the public UI gate.

    The plan and apply lease are reserved together. The existing guarded
    starter then atomically binds its queued job to that same plan and lease.
    """
    from app.services.engagement_teardown import assert_core_creation_allowed
    from app.services.provider_keyed_cleanup_visibility import (
        ProviderKeyedCleanupVisibilityError, require_digitalocean_cleanup_visibility,
    )
    from app.services.provider_catalog import (
        ProviderCatalogRegionSizeUnavailable, require_selected_digitalocean_region_sizes,
    )
    from app.services.credentials import decrypt_secret_value
    from app.services.provider_keyed_saved_plan_runner import _credential_snapshot
    from app.storage.credential_repository import SqlAlchemyCredentialRepository
    from app.services.guarded_test_deployment import (
        EXECUTION_CONFIRMATION, _require_configured_keyed_source,
        _target_for_engagement, start_guarded_pilot_standard_rti_run,
    )

    if runtime_value("ENVIRONMENT", "local") != "devtest":
        raise CoreDeploymentPlanError(["private keyed core apply requires DevTest"])
    assert_core_creation_allowed(engagement_id)
    engagement = get_engagement(engagement_id)
    if (engagement is None or engagement.sketch_state_schema != "provider-keyed-v2"
            or _target_for_engagement(engagement).name != "barragan-testing"):
        raise CoreDeploymentPlanError(["private keyed core target differs"])
    repo = SqlAlchemyDeploymentPlanRepository()
    plan = get_core_deployment_plan(engagement_id, plan_id, repository=repo)
    if (plan is None or plan.status != "ready" or plan.stage != "ready"
            or plan.apply_job_id or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or engagement.active_revision != plan.revision_id):
        raise CoreDeploymentPlanError(["reviewed keyed core plan is not ready"])
    _verify_plan_evidence(plan)
    authorization = plan.evidence.get("sketchAuthorization")
    mixed = (isinstance(authorization, Mapping)
             and authorization.get("kind") == "bounded-mixed-post-core-v1")
    if mixed:
        reviewed = plan.review.get("reviewedConfiguration") if isinstance(plan.review, dict) else None
        reviewed_core = reviewed.get("core") if isinstance(reviewed, Mapping) else None
        scopes = authorization.get("providerScopes")
        snapshots = plan.evidence.get("keyedProviderCredentialSnapshots")
        if (not isinstance(reviewed, Mapping)
                or reviewed.get("templateId") != "small-dev-infra"
                or reviewed_core != {"homebases": 1, "proxies": 1,
                                     "elkEnabled": False}
                or not isinstance(scopes, list) or len(scopes) != 2
                or {row.get("provider") for row in scopes if isinstance(row, Mapping)} !=
                {"linode", "digitalocean"}
                or not isinstance(snapshots, Mapping)
                or set(snapshots) != {"linode", "digitalocean"}):
            raise CoreDeploymentPlanError(["reviewed mixed Small Dev scope differs"])
        from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
        try:
            require_positive_control_ipv4(runtime_value("PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
        except Exception:
            raise CoreDeploymentPlanError([
                "mixed Inspector positive control is unavailable; no infrastructure mutation started"
            ]) from None
        counts = plan.review.get("counts")
        if (not isinstance(counts, Mapping) or type(counts.get("add")) is not int
                or counts["add"] <= 0 or counts.get("replace") != 0
                or counts.get("remove") != 0):
            raise CoreDeploymentPlanError(["mixed core plan is not add-only"])
    _require_configured_keyed_source()
    digitalocean_scope = (next((scope for scope in authorization["providerScopes"]
                                if scope["provider"] == "digitalocean"), None)
                          if mixed else authorization)
    connection_id = (digitalocean_scope.get("providerConnectionId")
                     if isinstance(digitalocean_scope, Mapping) else None)
    reviewed_credential = (plan.evidence["keyedProviderCredentialSnapshots"]["digitalocean"]
                           if mixed else plan.evidence.get("keyedProviderCredentialSnapshot"))
    try:
        require_digitalocean_cleanup_visibility(
            connection_id, reviewed_credential,
            transport=cleanup_visibility_transport,
        )
    except ProviderKeyedCleanupVisibilityError:
        raise CoreDeploymentPlanError([
            "selected DigitalOcean credential cannot prove scoped cleanup visibility"
        ]) from None
    try:
        digest, updated_at, encrypted = _credential_snapshot(
            connection_id, SqlAlchemyCredentialRepository())
        if (digest != reviewed_credential["encryptedSecretSha256"]
                or updated_at != reviewed_credential["updatedAt"]):
            raise ValueError("reviewed provider credential changed")
        token = decrypt_secret_value(encrypted)
        selections = [
            (node["region"], node["size"])
            for chain in (authorization["chains"] if not mixed else
                          [digitalocean_scope["chain"]])
            for node in [chain["middle"], *chain["edges"]]
        ]
        require_selected_digitalocean_region_sizes(
            token, selections, transport=region_catalog_transport,
        )
    except ProviderCatalogRegionSizeUnavailable as exc:
        raise CoreDeploymentPlanError([f"{exc}; no infrastructure mutation started"]) from None
    except Exception:
        raise CoreDeploymentPlanError([
            "selected DigitalOcean region catalog is incomplete or credential changed"
        ]) from None
    repo.begin_private_keyed_core_apply(plan)
    try:
        job = start_guarded_pilot_standard_rti_run(
            {"engagementId": engagement_id,
             "confirmMutation": EXECUTION_CONFIRMATION,
             "sshSourceCidrs": list(plan.evidence["sshSourceCidrs"])},
            prepared_core_run=dict(plan.evidence), core_plan_id=plan.id,
            core_plan_revision_id=plan.revision_id,
            background_runner=background_runner,
        )
    except Exception:
        current = repo.get(plan.id)
        if current is not None and current.apply_job_id:
            mark_bound_keyed_core_start_attention(plan.id, engagement_id, current.apply_job_id)
        else:
            repo.rollback_unbound_private_keyed_core_apply(plan)
        raise
    return repo.get(plan.id) or plan, job


def mark_bound_keyed_core_start_attention(plan_id: str, engagement_id: str, job_id: str) -> None:
    from app.storage.database import db
    from app.storage.models import DeploymentPlanModel

    DeploymentPlanModel.query.filter_by(
        id=plan_id, engagement_id=engagement_id,
        status="applying", apply_job_id=job_id,
    ).update({
        "status": "reconciliation_required", "stage": "reconciliation_required",
        "error": "bound core worker launch is uncertain; reconcile before retry",
    }, synchronize_session=False)
    db.session.commit()


def finish_core_deployment_plan_apply(plan_id: str, *, succeeded: bool) -> None:
    repo = SqlAlchemyDeploymentPlanRepository()
    plan = repo.get(plan_id)
    if plan is None or plan.status != "applying":
        return
    if not succeeded and plan.evidence.get("sketchStateSchema") == "provider-keyed-v2":
        repo.retain_failed_keyed_apply_fence(plan)
        return
    status = "applied" if succeeded else "reconciliation_required"
    operation = None
    if succeeded and plan.evidence.get("pendingSketchChainIds"):
        # The reviewed operation includes pending Sketch work. Keep the same
        # plan-owned engagement fence across the post-core continuation.
        operation = ("provider_keyed_initial" if plan.evidence.get("sketchStateSchema") == "provider-keyed-v2"
                     else "post_core")
    repo.complete_apply(replace(plan, status=status, stage=status), next_operation=operation)
    if succeeded:
        _cleanup_saved_plan_binary(plan)


def recover_interrupted_core_deployment_plans() -> None:
    from app.storage.database import db
    from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel

    for row in DeploymentPlanModel.query.filter(DeploymentPlanModel.status.in_(["preparing", "applying"])).all():
        if row.status == "preparing":
            row.status = "failed"
            row.stage = "failed"
            row.error = "plan preparation was interrupted and must be run again"
        else:
            row.status = "reconciliation_required"
            row.stage = "reconciliation_required"
            row.error = "plan apply was interrupted; reconcile infrastructure before continuing"
            if (isinstance(row.evidence, dict)
                    and row.evidence.get("sketchStateSchema") == "provider-keyed-v2"
                    and row.apply_job_id):
                # A reserved v2 worker may have crossed Terraform GO. Preserve
                # its exact plan-owned apply fence until read-only reconciliation.
                continue
        CoreMutationLeaseModel.query.filter_by(
            engagement_id=row.engagement_id, owner_id=row.id,
        ).filter(CoreMutationLeaseModel.operation.in_(["prepare", "apply"])).delete()
    db.session.commit()


def parse_terraform_plan_json(payload: Mapping[str, Any]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    counts = {key: 0 for key in ("add", "update", "replace", "remove", "read", "output")}
    rows: list[dict[str, Any]] = []
    for item in payload.get("resource_changes") or []:
        if not isinstance(item, Mapping):
            continue
        actions = list((item.get("change") or {}).get("actions") or [])
        action = _classify_actions(actions)
        if action is None:
            continue
        if action in counts:
            counts[action] += 1
        address = str(item.get("address") or "")
        resource_type = str(item.get("type") or "")
        provider_name = str(item.get("provider_name") or "")
        rows.append(
            {
                "action": action,
                "address": address,
                "type": resource_type,
                "provider": provider_name.rsplit("/", 1)[-1],
                "displayName": address.rsplit(".", 1)[-1],
                "group": _resource_group(resource_type),
            }
        )
    for change in (payload.get("output_changes") or {}).values():
        actions = list((change or {}).get("actions") or []) if isinstance(change, Mapping) else []
        if actions and actions != ["no-op"]:
            counts["output"] += 1
    return counts, rows


def _validate_oci_core_instance_baseline(
    payload: Mapping[str, Any], *, proxy_count: int, elk_enabled: bool
) -> None:
    expected = {
        "oci_core_instance.homebase",
        "oci_core_instance.proxy01",
    }
    if proxy_count == 2:
        expected.add("oci_core_instance.proxy02")
    if elk_enabled:
        expected.add("oci_core_instance.elk")
    planned = {
        str(resource.get("address") or ""): resource
        for resource in _planned_module_resources((payload.get("planned_values") or {}).get("root_module"))
        if resource.get("type") == "oci_core_instance"
    }
    dhcp = {
        str(resource.get("address") or ""): resource
        for resource in _planned_module_resources((payload.get("planned_values") or {}).get("root_module"))
        if resource.get("type") == "oci_core_default_dhcp_options"
    }
    missing = sorted(expected - set(planned))
    weakened = sorted(
        address
        for address in expected & set(planned)
        if not _has_required_oci_agent_config(planned[address].get("values"))
    )
    invalid_proxies = sorted(
        address
        for address in expected & set(planned)
        if address.startswith("oci_core_instance.proxy")
        and not _has_required_proxy_vnic_policy(planned[address].get("values"))
    )
    errors = [
        *[f"planned OCI core instance is missing: {address}" for address in missing],
        *[f"planned OCI core instance agent policy is missing or weakened: {address}" for address in weakened],
        *[f"planned OCI proxy source/destination check policy is missing or weakened: {address}" for address in invalid_proxies],
    ]
    default_dhcp = dhcp.get("oci_core_default_dhcp_options.pilot")
    if default_dhcp is None:
        errors.append("planned OCI default DHCP DNS policy is missing: oci_core_default_dhcp_options.pilot")
    elif not _has_required_oci_dhcp_policy(default_dhcp.get("values")):
        errors.append("planned OCI default DHCP DNS policy is missing or weakened: oci_core_default_dhcp_options.pilot")
    if errors:
        raise CoreDeploymentPlanError(errors)


def _planned_module_resources(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Mapping):
        return []
    resources = [resource for resource in value.get("resources") or [] if isinstance(resource, Mapping)]
    for child in value.get("child_modules") or []:
        resources.extend(_planned_module_resources(child))
    return resources


def _has_required_oci_agent_config(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    config = value.get("agent_config")
    config = config[0] if isinstance(config, list) and len(config) == 1 else config
    if not isinstance(config, Mapping):
        return False
    required = OCI_CORE_INSTANCE_AGENT_POLICY
    plugins = config.get("plugins_config")
    plugins = plugins if isinstance(plugins, list) else []
    required_plugin = required["plugins_config"]
    return (
        config.get("are_all_plugins_disabled") is required["are_all_plugins_disabled"]
        and config.get("is_monitoring_disabled") is required["is_monitoring_disabled"]
        and len(plugins) == 1
        and isinstance(plugins[0], Mapping)
        and plugins[0].get("name") == required_plugin["name"]
        and plugins[0].get("desired_state") == required_plugin["desired_state"]
    )


def _has_required_proxy_vnic_policy(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    vnics = value.get("create_vnic_details")
    vnic = vnics[0] if isinstance(vnics, list) and len(vnics) == 1 else None
    return isinstance(vnic, Mapping) and vnic.get("skip_source_dest_check") is OCI_CORE_PROXY_SKIP_SOURCE_DEST_CHECK


def _has_required_oci_dhcp_policy(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    options = value.get("options")
    option = options[0] if isinstance(options, list) and len(options) == 1 else None
    if not isinstance(option, Mapping):
        return False
    dns_servers = option.get("custom_dns_servers")
    return (
        option.get("type") == "DomainNameServer"
        and option.get("server_type") == "CustomDnsServer"
        and isinstance(dns_servers, list)
        and tuple(str(server) for server in dns_servers) == OCI_CORE_DHCP_DNS_SERVERS
    )


def _prepare_core_deployment_plan(
    plan_id: str,
    cidrs: list[str],
    *,
    repository: DeploymentPlanRepository,
    command_runner: CommandRunner | None,
    engagement_workspace_root: Path,
    terraform_state_root: Path,
) -> None:
    plan = repository.get(plan_id)
    if plan is None:
        return
    plan_path: Path | None = None
    try:
        engagement = get_engagement(plan.engagement_id)
        if engagement is None:
            raise CoreDeploymentPlanError(["engagement not found"])
        from app.services.guarded_test_deployment import _proxy_count_for_engagement, _target_for_engagement

        target = _target_for_engagement(engagement)
        revision = get_revision(plan.revision_id) or {}
        template_id = str(revision.get("templateId") or engagement.template_id or "standard-rti")
        parameters = dict(revision.get("inputParameters") or {})
        profile = resolve_oci_compute_profile(template_id)
        elk_enabled = parameters.get("elkEnabled") is True
        durable = prepare_core_deployment_run(
            plan.engagement_id,
            root=engagement_workspace_root,
            state_root=terraform_state_root,
            run_id=f"core-{uuid4().hex}",
        )
        workspace = render_pilot_standard_rti_workspace(
            durable.run_directory,
            target,
            engagement_name=engagement.name,
            engagement_id=engagement.id,
            engagement_repos_root=engagement_workspace_root,
            proxy_count=_proxy_count_for_engagement(engagement),
            template_id=template_id,
            elk_enabled=elk_enabled,
            compute_profile=profile,
            host_image_profile=managed_host_image_profile_named(
                durable.managed_host_image_profile_name
            ),
            retained_oci_source_image_id=durable.retained_oci_source_image_id,
        )
        terraform = resolve_terraform().command
        if not terraform:
            raise RuntimeError("terraform executable was not resolved")
        public_key = os.environ.get(SSH_PUBLIC_KEY_ENV, "").strip()
        private_key = os.environ.get(SSH_PRIVATE_KEY_ENV, "").strip()
        if not public_key or not private_key:
            raise RuntimeError("configured core SSH key pair is required to prepare a plan")
        env = {**barragan_subprocess_env(), "TF_DATA_DIR": str(durable.terraform_data_dir)}
        run = command_runner or _run_command
        _checked(run([terraform, "init", "-input=false"], durable.run_directory, env), "terraform init")
        keyed_source_manifest = (
            build_keyed_core_terraform_source_manifest(durable.run_directory)
            if engagement.sketch_state_schema == "provider-keyed-v2" else None
        )
        plan_path = durable.run_directory / PLAN_FILENAME
        state_arg = f"-state={durable.state_path}"
        plan_result = run(
            [
                terraform, "plan", "-input=false", "-detailed-exitcode", f"-out={plan_path}", state_arg,
                "-var", f"region={target.region}", "-var", f"compartment_ocid={target.compartment_id}",
                "-var", f"ssh_public_key_path={public_key}", "-var", f"ssh_source_cidrs={json.dumps(cidrs)}",
            ],
            durable.run_directory,
            env,
        )
        if plan_result.returncode not in {0, 2}:
            raise RuntimeError("terraform plan failed")
        if not plan_path.is_file():
            raise RuntimeError("terraform did not create the saved plan artifact")
        os.chmod(plan_path, 0o600)
        show_json = _checked(run([terraform, "show", "-json", str(plan_path)], durable.run_directory, env), "terraform show")
        # Execute Terraform's human-readable rendering as additional evidence,
        # but never persist it: provider values may be sensitive. The API text
        # below is reconstructed solely from allowlisted addresses/actions.
        show_text = _checked(run([terraform, "show", "-no-color", str(plan_path)], durable.run_directory, env), "terraform show text")
        if keyed_source_manifest is not None:
            require_keyed_core_terraform_source_manifest(durable.run_directory, keyed_source_manifest)
        payload = json.loads(show_json.stdout)
        _validate_oci_core_instance_baseline(
            payload,
            proxy_count=workspace.proxy_count,
            elk_enabled=workspace.elk_enabled,
        )
        counts, rows = parse_terraform_plan_json(payload)
        destructive = counts["replace"] + counts["remove"]
        status = "no_changes" if plan_result.returncode == 0 else ("failed" if destructive else "ready")
        error = "new infrastructure plans cannot replace or remove resources" if destructive else ""
        prepared_at = datetime.now(timezone.utc)
        post_core_scope, pending_chain_ids, sketch_intent_fingerprint, pending_chain_fingerprints = _reviewed_post_core_scope(
            plan.engagement_id, revision
        )
        _assert_reviewable_sketch_schema(engagement, revision)
        post_core_scope = {**post_core_scope, "sketchStateSchema": engagement.sketch_state_schema}
        from app.services.catalog import get_template

        template = get_template(template_id)
        profile_name = template.summary.name if template is not None else template_id
        compute_profile = _public_compute_profile(profile, profile_name, workspace.proxy_count, elk_enabled)
        fingerprint_inputs = {
            "revisionId": plan.revision_id,
            "cidrs": cidrs,
            "managedHostImageProfile": durable.managed_host_image_profile_name,
        }
        keyed_digitalocean_image = None
        keyed_linode_image = None
        sketch_authorization = None
        keyed_credential_snapshot = None
        if engagement.sketch_state_schema == "provider-keyed-v2":
            fingerprint_inputs["sketchStateSchema"] = engagement.sketch_state_schema
            keyed_profile = managed_host_image_profile_named(durable.managed_host_image_profile_name)
            keyed_digitalocean_image = keyed_profile.digitalocean_image
            fingerprint_inputs["digitaloceanImage"] = keyed_digitalocean_image
            if _is_mixed_keyed_scope(post_core_scope):
                keyed_linode_image = keyed_profile.linode_image
                fingerprint_inputs["linodeImage"] = keyed_linode_image
            sketch_authorization = _reviewed_keyed_sketch_authorization(
                plan.engagement_id, post_core_scope, pending_chain_fingerprints,
                keyed_digitalocean_image, keyed_linode_image,
            )
            if keyed_linode_image is None:
                keyed_credential_snapshot = _reviewed_keyed_credential_snapshot(
                    sketch_authorization["providerConnectionId"])
            else:
                keyed_credential_snapshot = {
                    provider_scope["provider"]: _reviewed_keyed_credential_snapshot(
                        provider_scope["providerConnectionId"], provider_scope["provider"])
                    for provider_scope in sketch_authorization["providerScopes"]
                }
            fingerprint_inputs["sketchAuthorizationFingerprint"] = sketch_authorization["fingerprint"]
        input_fingerprint = _json_hash(fingerprint_inputs)
        review = {
            "counts": counts,
            "resourceChanges": rows,
            "target": {"name": target.name, "region": target.region},
            "ageWarningAt": (prepared_at + timedelta(minutes=60)).isoformat(),
            "sanitizedText": sanitize_terraform_plan_text(show_text.stdout),
            "sanitizedTextKind": "terraform_plan",
            "terraformFiles": _safe_sources(durable.run_directory),
            "sshSourceCidrs": cidrs,
            "inputFingerprint": input_fingerprint,
            "reviewedConfiguration": {
                "templateId": template_id,
                "templateName": template.summary.name if template is not None else template_id,
                "core": {
                    "homebases": 1,
                    "proxies": int(parameters.get("proxyCount") or workspace.proxy_count),
                    "elkEnabled": parameters.get("elkEnabled") is True,
                },
                "target": {"name": target.name, "region": target.region},
                "sshSourceCidrs": cidrs,
                "computeProfile": compute_profile,
            },
            "computeProfile": compute_profile,
            "postCoreScope": post_core_scope,
            "sketchStateSchema": engagement.sketch_state_schema,
        }
        if keyed_digitalocean_image is not None:
            review["digitaloceanImage"] = keyed_digitalocean_image
            review["reviewedConfiguration"]["digitaloceanImage"] = keyed_digitalocean_image
            review["reviewedConfiguration"]["sketchAuthorization"] = sketch_authorization
            if keyed_linode_image is not None:
                review["linodeImage"] = keyed_linode_image
                review["reviewedConfiguration"]["linodeImage"] = keyed_linode_image
        evidence = {
            "runDirectory": str(durable.run_directory),
            "terraformDataDir": str(durable.terraform_data_dir),
            "terraformStatePath": str(durable.state_path),
            "terraformStateLocator": durable.state_locator,
            "planPath": str(plan_path),
            "planFingerprint": _file_hash(plan_path),
            "stateFingerprint": _file_hash(durable.state_path),
            "sourceFingerprint": _tree_hash(durable.run_directory, exclude={PLAN_FILENAME}),
            "bundleFingerprint": _tree_hash(durable.run_directory / "ansible"),
            "providerLockFingerprint": _file_hash(durable.run_directory / ".terraform.lock.hcl"),
            "terraformFingerprint": _terraform_version(terraform, durable.run_directory, env, run),
            "publicKeyFingerprint": _file_hash(Path(public_key)),
            "privateKeyFingerprint": _file_hash(Path(private_key)),
            "inputFingerprint": input_fingerprint,
            "revisionFingerprint": _json_hash(get_revision(plan.revision_id)),
            "capabilitySelectionFingerprint": _json_hash(durable.workspace.metadata),
            "targetFingerprint": _json_hash({"name": target.name, "region": target.region, "compartmentId": target.compartment_id}),
            "sshSourceCidrs": cidrs,
            "sshPrivateKeyPath": private_key,
            "sshPublicKeyPath": public_key,
            "proxyCount": workspace.proxy_count,
            "templateId": template_id,
            "elkEnabled": elk_enabled,
            "computeProfileSnapshot": profile.to_dict(),
            "managedHostImageProfile": durable.managed_host_image_profile_name,
            "computeProfileFingerprint": profile.fingerprint,
            "ociCoreInstanceBaselineFingerprint": OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
            "pendingSketchChainIds": pending_chain_ids,
            "pendingSketchChainFingerprints": pending_chain_fingerprints,
            "sketchIntentFingerprint": sketch_intent_fingerprint,
            "sketchStateSchema": engagement.sketch_state_schema,
            "target": {"name": target.name, "region": target.region, "compartmentId": target.compartment_id, "auth": target.auth},
        }
        if keyed_digitalocean_image is not None:
            evidence["digitaloceanImage"] = keyed_digitalocean_image
            evidence["sketchAuthorization"] = sketch_authorization
            if keyed_linode_image is None:
                evidence["keyedProviderCredentialSnapshot"] = keyed_credential_snapshot
            else:
                evidence["linodeImage"] = keyed_linode_image
                evidence["keyedProviderCredentialSnapshots"] = keyed_credential_snapshot
            evidence["keyedCoreTerraformSourceManifest"] = keyed_source_manifest
        repository.save(replace(plan, status=status, stage=status, review=review, evidence=evidence, prepared_at=prepared_at.isoformat(), error=error))
    except Exception as exc:
        if plan_path is not None and plan_path.is_file():
            plan_path.unlink(missing_ok=True)
        current = repository.get(plan_id) or plan
        repository.save(replace(current, status="failed", stage="failed", error=_safe_error(exc)))
    finally:
        repository.release(plan.engagement_id, plan.id)


def _verify_plan_evidence(plan: DeploymentPlan) -> None:
    evidence = plan.evidence
    if evidence.get("sketchStateSchema", "split-v1") == "provider-keyed-v2":
        require_keyed_core_terraform_source_manifest(
            Path(str(evidence.get("runDirectory") or "")), evidence.get("keyedCoreTerraformSourceManifest")
        )
    checks = {
        "saved plan": _file_hash(Path(str(evidence.get("planPath") or ""))) == evidence.get("planFingerprint"),
        "Terraform source": _tree_hash(Path(str(evidence.get("runDirectory") or "")), exclude={PLAN_FILENAME}) == evidence.get("sourceFingerprint"),
        "Ansible bundle": _tree_hash(Path(str(evidence.get("runDirectory") or "")) / "ansible") == evidence.get("bundleFingerprint"),
        "provider lock": _file_hash(Path(str(evidence.get("runDirectory") or "")) / ".terraform.lock.hcl") == evidence.get("providerLockFingerprint"),
        "Terraform state": _file_hash(Path(str(evidence.get("terraformStatePath") or ""))) == evidence.get("stateFingerprint"),
        "public SSH key": _file_hash(Path(str(evidence.get("sshPublicKeyPath") or ""))) == evidence.get("publicKeyFingerprint"),
        "private SSH key": _file_hash(Path(str(evidence.get("sshPrivateKeyPath") or ""))) == evidence.get("privateKeyFingerprint"),
        "OCI core instance baseline": evidence.get("ociCoreInstanceBaselineFingerprint") == OCI_CORE_INSTANCE_BASELINE_FINGERPRINT,
    }
    failed = [label for label, ok in checks.items() if not ok]
    engagement = get_engagement(plan.engagement_id)
    if engagement is None or engagement.active_revision != plan.revision_id:
        failed.append("deployment revision")
    if engagement is None or getattr(engagement, "sketch_state_schema", "split-v1") != evidence.get("sketchStateSchema", "split-v1"):
        failed.append("Sketch state schema")
    if engagement is not None:
        from app.services.guarded_test_deployment import _target_for_engagement

        target = _target_for_engagement(engagement)
        expected_target = _json_hash({"name": target.name, "region": target.region, "compartmentId": target.compartment_id})
        if expected_target != evidence.get("targetFingerprint"):
            failed.append("deployment target")
    revision = get_revision(plan.revision_id) or {}
    template_id = str(revision.get("templateId") or (engagement.template_id if engagement is not None else "") or "standard-rti")
    try:
        current_profile = resolve_oci_compute_profile(template_id)
        if (
            current_profile.fingerprint != evidence.get("computeProfileFingerprint")
            or current_profile.to_dict() != evidence.get("computeProfileSnapshot")
        ):
            failed.append("compute profile")
    except Exception:
        failed.append("compute profile")
    fingerprint_inputs = {
        "revisionId": plan.revision_id,
        "cidrs": list(evidence.get("sshSourceCidrs") or []),
        "managedHostImageProfile": evidence.get("managedHostImageProfile"),
    }
    if evidence.get("sketchStateSchema", "split-v1") == "provider-keyed-v2":
        fingerprint_inputs["sketchStateSchema"] = "provider-keyed-v2"
        fingerprint_inputs["digitaloceanImage"] = evidence.get("digitaloceanImage")
        authorization = evidence.get("sketchAuthorization")
        if isinstance(authorization, Mapping) and authorization.get("kind") == "bounded-mixed-post-core-v1":
            fingerprint_inputs["linodeImage"] = evidence.get("linodeImage")
        fingerprint_inputs["sketchAuthorizationFingerprint"] = (
            authorization.get("fingerprint") if isinstance(authorization, Mapping) else None
        )
        if not _reviewed_keyed_image_matches(evidence):
            failed.append("DigitalOcean image")
        try:
            if not _reviewed_keyed_credentials_match(evidence):
                failed.append("provider credential")
        except CoreDeploymentPlanError:
            failed.append("provider credential")
    expected_input = _json_hash(fingerprint_inputs)
    if expected_input != evidence.get("inputFingerprint"):
        failed.append("deployment inputs")
    if _json_hash(get_revision(plan.revision_id)) != evidence.get("revisionFingerprint"):
        failed.append("deployment revision content")
    from app.storage.engagement_workspace_repository import SqlAlchemyEngagementWorkspaceRepository

    workspace = SqlAlchemyEngagementWorkspaceRepository().get(plan.engagement_id)
    if workspace is None or _json_hash(workspace.metadata) != evidence.get("capabilitySelectionFingerprint"):
        failed.append("capability selection")
    try:
        _assert_reviewable_sketch_schema(engagement, revision)
        _scope, _ids, current_sketch_fingerprint, _fingerprints = _reviewed_post_core_scope(plan.engagement_id, revision)
        if current_sketch_fingerprint != evidence.get("sketchIntentFingerprint"):
            failed.append("post-core sketch intent")
        if evidence.get("sketchStateSchema") == "provider-keyed-v2" and (
            _reviewed_keyed_sketch_authorization(
                plan.engagement_id, _scope, _fingerprints,
                evidence.get("digitaloceanImage"), evidence.get("linodeImage")
            ) != evidence.get("sketchAuthorization")
            or (plan.review.get("reviewedConfiguration") or {}).get("sketchAuthorization") != evidence.get("sketchAuthorization")
        ):
            failed.append("Sketch authorization")
    except (CoreDeploymentPlanError, ValueError):
        failed.append("post-core sketch intent")
    terraform = resolve_terraform().command
    if not terraform:
        failed.append("Terraform runtime")
    else:
        try:
            env = {**barragan_subprocess_env(), "TF_DATA_DIR": str(evidence.get("terraformDataDir") or "")}
            current_version = _terraform_version(terraform, Path(str(evidence.get("runDirectory") or "")), env, _run_command)
            if current_version != evidence.get("terraformFingerprint"):
                failed.append("Terraform runtime")
        except Exception:
            failed.append("Terraform runtime")
    if failed:
        raise CoreDeploymentPlanError([f"deployment plan integrity check failed: {', '.join(failed)}"])


def _public_compute_profile(profile, name: str, proxy_count: int, elk_enabled: bool) -> dict[str, Any]:
    return {
        "id": profile.template_id,
        "name": name,
        "fingerprint": profile.fingerprint,
        "bootVolumeSizeGiB": profile.boot_volume_size_in_gbs,
        "roles": [
            {
                "role": role,
                "label": label,
                "nodeCount": node_count,
                "shape": sizing.shape,
                "ocpus": sizing.ocpus,
                "memoryGiB": sizing.memory_in_gbs,
            }
            for role, label, node_count, sizing in (
                ("homebase", "Homebase", 1, profile.homebase),
                ("proxy", "Proxy", proxy_count, profile.proxy),
                ("elk", "ELK", 1 if elk_enabled else 0, profile.elk),
            )
        ],
    }


def _classify_actions(actions: list[str]) -> str | None:
    if actions in (["delete", "create"], ["create", "delete"]):
        return "replace"
    return {
        ("create",): "add",
        ("update",): "update",
        ("delete",): "remove",
        ("read",): "read",
        ("no-op",): "no_op",
    }.get(tuple(actions))


def _resource_group(resource_type: str) -> str:
    if "instance" in resource_type:
        return "Compute"
    if any(value in resource_type for value in ("vcn", "subnet", "gateway", "route", "security")):
        return "Network"
    return "Other"


def _sanitized_text(counts: Mapping[str, int], rows: list[dict[str, Any]]) -> str:
    header = "Sanitized plan summary (not full Terraform output): " + ", ".join(
        f"{key}={counts[key]}" for key in ("add", "update", "replace", "remove", "read", "output")
    )
    return "\n".join([header, *[f"{row['action'].upper()} {row['address']}" for row in rows]])


def sanitize_terraform_plan_text(value: str) -> str:
    """Preserve Terraform's complete plan structure while removing all values.

    This intentionally redacts more than Terraform's own sensitive marker. Any
    unsafe/binary/oversized rendering fails preparation instead of returning a
    partial artifact that could be mistaken for complete evidence.
    """
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("terraform plan text was empty")
    if len(value.encode("utf-8")) > 524_288 or "\x00" in value:
        raise RuntimeError("terraform plan text exceeded the safe evidence boundary")
    sensitive = re.compile(
        r"(?i)(password|secret|token|private[_ -]?key|public[_ -]?key[_ -]?path|"
        r"ssh[_ -]?authorized[_ -]?keys|user[_ -]?data|credential)"
    )
    assignment = re.compile(r"^(\s*[+~\-]?\s*[^=\n]+?\s*=\s*)(.*)$")
    heredoc_start = re.compile(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)")
    key_material = re.compile(
        r"(?i)\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[^\s]+)\s+[A-Za-z0-9+/=]+(?:\s+[^\r\n]+)?"
    )
    absolute_path = re.compile(r"(?<![A-Za-z0-9_.-])/(?:[^\s\"']+/)*[^\s\"']+")
    env_reference = re.compile(r"\$\{?[A-Z][A-Z0-9_]{2,}\}?")
    quoted_literal = re.compile(r'"(?:\\.|[^"\\])*"')
    network_literal = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
    sanitized: list[str] = []
    heredoc_marker: str | None = None
    for line in value.splitlines():
        if len(line) > 10_000 or any(ord(character) < 9 for character in line):
            raise RuntimeError("terraform plan text contained an unsafe line")
        if heredoc_marker is not None:
            if line.strip() == heredoc_marker:
                heredoc_marker = None
            continue
        match = assignment.match(line)
        if match:
            label = match.group(1)
            raw_value = match.group(2)
            marker_match = heredoc_start.search(raw_value)
            if marker_match:
                heredoc_marker = marker_match.group(1)
            line = f"{label}<redacted>" if not sensitive.search(label) else f"{label.split('=')[0].rstrip()} = <sensitive attribute redacted>"
        else:
            line = quoted_literal.sub('"<redacted string>"', line)
            line = key_material.sub("<key material redacted>", line)
            line = network_literal.sub("<network value redacted>", line)
            line = absolute_path.sub("<path redacted>", line)
            line = env_reference.sub("<environment reference redacted>", line)
        sanitized.append(line)
    result = "\n".join(sanitized)
    if heredoc_marker is not None or absolute_path.search(result) or env_reference.search(result) or key_material.search(result):
        raise RuntimeError("terraform plan text could not be sanitized safely")
    return result


def _reviewed_post_core_scope(
    engagement_id: str, revision: Mapping[str, Any]
) -> tuple[dict[str, Any], list[str], str, dict[str, str]]:
    chains = list((revision.get("resolvedTopology") or {}).get("sketchChains") or [])
    input_chains = list((revision.get("inputParameters") or {}).get("sketchChains") or [])
    stored = SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
    from app.services.sketch_chains import _same_template_chain_intent, _template_chain_intent

    safe_chains: list[dict[str, Any]] = []
    used_record_ids: set[str] = set()
    for index, chain in enumerate(chains):
        logical_id = str(chain.get("id") or f"chain-{index + 1}")
        body = input_chains[index] if index < len(input_chains) and isinstance(input_chains[index], Mapping) else chain
        intent = _template_chain_intent(engagement_id, dict(body))
        record = next(
            (
                candidate for candidate in stored
                if candidate.chain_id not in used_record_ids
                and candidate.status == "pending"
                and _same_template_chain_intent(candidate, intent)
            ),
            None,
        )
        if record is None:
            raise CoreDeploymentPlanError([f"reviewed sketch chain {logical_id} has no matching pending rollout record"])
        used_record_ids.add(record.chain_id)
        expected = (
            record.assigned_proxy, record.middle_provider, record.middle_region,
            record.edge_provider, record.edge_region, record.edge_count,
        )
        edges = list(chain.get("edges") or []) or [
            {"id": f"edge-{index:02d}", "provider": chain.get("edgeProvider"), "region": chain.get("edgeRegion")}
            for index in range(1, expected[-1] + 1)
        ]
        safe_chains.append({
            "id": record.chain_id,
            "intentId": logical_id,
            "assignedProxy": expected[0],
            "middle": {"provider": expected[1], "region": expected[2]},
            "edges": [
                {"id": str(edge.get("id") or ""), "provider": str(edge.get("provider") or ""), "region": str(edge.get("region") or "")}
                for edge in edges
            ],
        })
    providers = sorted({
        value
        for chain in safe_chains
        for value in [chain["middle"]["provider"], *[edge["provider"] for edge in chain["edges"]]]
        if value
    })
    scope = {
        "chainCount": len(safe_chains),
        "middleCount": len(safe_chains),
        "edgeCount": sum(len(chain["edges"]) for chain in safe_chains),
        "providers": providers,
        "chains": safe_chains,
    }
    from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint

    pending_ids = [chain["id"] for chain in safe_chains]
    fingerprints = {
        chain_id: sketch_chain_intent_fingerprint(
            next(record for record in stored if record.chain_id == chain_id)
        )
        for chain_id in pending_ids
    }
    return scope, pending_ids, _json_hash(safe_chains), fingerprints


def _is_mixed_keyed_scope(scope: Mapping[str, Any]) -> bool:
    chains = scope.get("chains")
    return (isinstance(chains, list) and len(chains) == 2
            and {str((chain.get("middle") or {}).get("provider"))
                 for chain in chains if isinstance(chain, Mapping)} ==
            {"linode", "digitalocean"})


def _reviewed_mixed_keyed_sketch_authorization(
    engagement_id: str, scope: Mapping[str, Any], fingerprints: Mapping[str, str],
    digitalocean_image: str, linode_image: str,
) -> dict[str, Any]:
    """Seal two initial provider scopes without authorizing Sketch execution."""
    from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
    from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
    from app.services.provider_keyed_sketch import resolve_default_provider_connection

    chains = scope["chains"]
    records = {row.chain_id: row for row in
               SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
               if row.status == "pending"}
    if (len(records) != 2 or set(records) != {chain.get("id") for chain in chains}
            or any(not isinstance(value, str) or not value
                   for value in (digitalocean_image, linode_image))):
        raise CoreDeploymentPlanError(["reviewed mixed Sketch chain set differs"])
    images = {"linode": linode_image, "digitalocean": digitalocean_image}
    provider_scopes = []
    for provider in ("digitalocean", "linode"):
        matching = [chain for chain in chains
                    if chain["middle"].get("provider") == provider]
        if len(matching) != 1:
            raise CoreDeploymentPlanError(["reviewed mixed Sketch provider scope differs"])
        chain = matching[0]
        record = records[chain["id"]]
        edges = record.edge_intents or []
        if (record.middle_provider != provider or record.edge_provider != provider
                or record.edge_count != 1 or len(edges) != 1
                or fingerprints.get(record.chain_id) != sketch_chain_intent_fingerprint(record)
                or record.assigned_proxy != chain.get("assignedProxy")
                or record.middle_region != chain["middle"].get("region")
                or chain["middle"].get("provider") != provider
                or len(chain.get("edges") or []) != 1
                or any(edges[0].get(key) != chain["edges"][0].get(key)
                       for key in ("id", "provider", "region"))
                or edges[0].get("provider") != provider
                or edges[0].get("size") != record.edge_size):
            raise CoreDeploymentPlanError(["reviewed mixed Sketch record differs"])
        try:
            connection_id = resolve_default_provider_connection(provider)
        except ValueError as exc:
            raise CoreDeploymentPlanError([
                f"default {provider} provider connection is unavailable"]) from exc
        provider_scopes.append({
            "provider": provider, "providerConnectionId": connection_id,
            "image": images[provider],
            "source": {
                "revision": _SOURCE_REVISION,
                "templateSha256": (_SOURCE_SHA256 if provider == "digitalocean"
                                   else KEYED_LINODE_SOURCE_SHA256),
                "providerLock": {
                    "path": "barragan-v2/.terraform.lock.hcl",
                    "sha256": (KEYED_DIGITALOCEAN_LOCK_SHA256 if provider == "digitalocean"
                               else KEYED_LINODE_LOCK_SHA256),
                    "providerVersion": "2.103.0" if provider == "digitalocean" else "4.5.0",
                },
            },
            "firewall": {
                "publicTcpPorts": ["80", "443", "2222"],
                "publicUdpPorts": [], "publicIpv6Allowed": False,
                "managementSsh": {
                    "port": 22, "sourceRule": "selected-proxy-public-ipv4-32",
                    "proxyNames": [record.assigned_proxy],
                },
                "peerIngress": {
                    "protocols": ["tcp", "udp", "icmp"], "portRange": "1-65535",
                    "sourceRule": "all-created-provider-middle-and-edge-public-ipv4-32",
                },
                "outboundIpv4": (
                    "accept" if provider == "linode" else [
                        {"protocol": protocol, "portRange": "1-65535",
                         "destination": "0.0.0.0/0"} for protocol in ("tcp", "udp")
                    ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}]),
                "outboundIpv6": "drop" if provider == "linode" else "not-configured",
            },
            "chain": {
                "id": record.chain_id, "fingerprint": fingerprints[record.chain_id],
                "assignedProxy": record.assigned_proxy,
                "middle": {"provider": provider, "region": record.middle_region,
                           "size": record.middle_size},
                "edges": [{"id": edges[0]["id"], "provider": provider,
                           "region": edges[0]["region"], "size": record.edge_size}],
            },
        })
    result = {"kind": "bounded-mixed-post-core-v1", "providerScopes": provider_scopes}
    result["fingerprint"] = _json_hash(result)
    return result


def _reviewed_keyed_sketch_authorization(
    engagement_id: str,
    scope: Mapping[str, Any],
    fingerprints: Mapping[str, str],
    image: Any, linode_image: Any = None,
) -> dict[str, Any]:
    """Bound the post-core provider plan without inventing unknown proxy IPs.

    This is review evidence, not permission to apply a Sketch plan. The
    post-core saved-plan gate must compare every concrete value to this scope.
    """

    from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
    from app.services.provider_keyed_initial_plan_gate import _SOURCE_REVISION, _SOURCE_SHA256
    from app.services.provider_keyed_sketch import resolve_default_provider_connection

    chains = scope.get("chains")
    if _is_mixed_keyed_scope(scope):
        return _reviewed_mixed_keyed_sketch_authorization(
            engagement_id, scope, fingerprints, image, linode_image)
    if (not isinstance(chains, list) or len(chains) != 2
            or not isinstance(image, str) or not image):
        raise CoreDeploymentPlanError(["reviewed keyed Sketch scope is incomplete"])
    records = {
        row.chain_id: row
        for row in SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
        if row.status == "pending"
    }
    if len(records) != 2 or set(records) != {chain.get("id") for chain in chains if isinstance(chain, Mapping)}:
        raise CoreDeploymentPlanError(["reviewed keyed Sketch chain set differs from pending records"])
    reviewed_chains: list[dict[str, Any]] = []
    middle_sizes: set[str] = set()
    edge_sizes: set[str] = set()
    for chain in chains:
        chain_id = chain.get("id") if isinstance(chain, Mapping) else None
        record = records.get(chain_id)
        if (record is None or fingerprints.get(chain_id) != sketch_chain_intent_fingerprint(record)
                or record.middle_provider != "digitalocean" or record.edge_provider != "digitalocean"
                or record.assigned_proxy != chain.get("assignedProxy")
                or record.middle_region != (chain.get("middle") or {}).get("region")):
            raise CoreDeploymentPlanError(["reviewed keyed Sketch record differs from scope"])
        edges = list(record.edge_intents or [])
        if (not edges or len(edges) != record.edge_count or len(edges) != len(chain.get("edges") or [])
                or any(
                    edge.get("id") != expected.get("id")
                    or edge.get("region") != expected.get("region")
                    or edge.get("provider") != expected.get("provider")
                    or edge.get("provider") != "digitalocean"
                    or edge.get("size") != record.edge_size
                    for edge, expected in zip(edges, chain["edges"])
                )):
            raise CoreDeploymentPlanError(["reviewed keyed Sketch edges differ from scope"])
        middle_sizes.add(record.middle_size)
        edge_sizes.add(record.edge_size)
        reviewed_chains.append({
            "id": chain_id,
            "fingerprint": fingerprints[chain_id],
            "assignedProxy": record.assigned_proxy,
            "middle": {"provider": record.middle_provider, "region": record.middle_region, "size": record.middle_size},
            "edges": [
                {"id": edge["id"], "provider": edge["provider"], "region": edge["region"], "size": edge["size"]}
                for edge in edges
            ],
        })
    if len({chain["id"] for chain in reviewed_chains}) != 2 or len(middle_sizes) != 1 or len(edge_sizes) != 1:
        raise CoreDeploymentPlanError(["reviewed keyed Sketch chains are not a compatible provider scope"])
    try:
        connection_id = resolve_default_provider_connection("digitalocean")
    except ValueError as exc:
        raise CoreDeploymentPlanError(["default DigitalOcean provider connection is unavailable"]) from exc
    authorization: dict[str, Any] = {
        "kind": "bounded-post-core",
        "provider": "digitalocean",
        "providerConnectionId": connection_id,
        "source": {
            "revision": _SOURCE_REVISION,
            "templateSha256": _SOURCE_SHA256,
            "providerLock": {
                "path": "barragan-v2/.terraform.lock.hcl",
                "sha256": KEYED_DIGITALOCEAN_LOCK_SHA256,
                "digitaloceanVersion": "2.103.0",
            },
        },
        "image": image,
        "chains": reviewed_chains,
        "firewall": {
            "publicTcpPorts": ["80", "443", "2222"],
            "publicUdpPorts": [],
            "publicIpv6Allowed": False,
            "managementSsh": {
                "port": 22,
                "sourceRule": "selected-proxy-public-ipv4-32",
                "proxyNames": sorted({chain["assignedProxy"] for chain in reviewed_chains}),
            },
            "peerIngress": {
                "protocols": ["tcp", "udp", "icmp"],
                "portRange": "1-65535",
                "sourceRule": "all-created-middle-and-edge-public-ipv4-32",
            },
            "outboundIpv4": [
                {"protocol": protocol, "portRange": "1-65535", "destination": "0.0.0.0/0"}
                for protocol in ("tcp", "udp")
            ] + [{"protocol": "icmp", "destination": "0.0.0.0/0"}],
        },
    }
    authorization["fingerprint"] = _json_hash(authorization)
    return authorization


def _reviewed_keyed_credential_snapshot(
    connection_id: Any, provider: str = "digitalocean",
) -> dict[str, str]:
    """Private review evidence for a credential generation, never API data."""

    from app.storage.credential_repository import SqlAlchemyCredentialRepository

    if not isinstance(connection_id, str) or not connection_id:
        raise CoreDeploymentPlanError(["reviewed provider connection is invalid"])
    repository = SqlAlchemyCredentialRepository()
    credential = repository.get(connection_id)
    if provider not in {"linode", "digitalocean"}:
        raise CoreDeploymentPlanError(["reviewed provider is unsupported"])
    default = repository.get_default(provider)
    if (credential is None or default is None or credential.id != default.id
            or credential.id != connection_id or credential.provider != provider
            or default.provider != provider or credential.status != "active"
            or default.status != "active" or credential.is_default is not True
            or default.is_default is not True
            or not isinstance(credential.encrypted_secret, str) or not credential.encrypted_secret
            or credential.encrypted_secret != default.encrypted_secret
            or credential.updated_at != default.updated_at):
        raise CoreDeploymentPlanError(["reviewed provider credential changed or is unavailable"])
    return {
        "encryptedSecretSha256": hashlib.sha256(credential.encrypted_secret.encode("utf-8")).hexdigest(),
        "updatedAt": credential.updated_at,
    }


def _reviewed_keyed_credentials_match(evidence: Mapping[str, Any]) -> bool:
    authorization = evidence.get("sketchAuthorization")
    if not isinstance(authorization, Mapping):
        return False
    if authorization.get("kind") != "bounded-mixed-post-core-v1":
        return (_reviewed_keyed_credential_snapshot(
            authorization.get("providerConnectionId")) ==
            evidence.get("keyedProviderCredentialSnapshot"))
    scopes = authorization.get("providerScopes")
    if (not isinstance(scopes, list) or len(scopes) != 2
            or [scope.get("provider") for scope in scopes
                if isinstance(scope, Mapping)] != ["digitalocean", "linode"]
            or "keyedProviderCredentialSnapshot" in evidence):
        return False
    return {
        scope["provider"]: _reviewed_keyed_credential_snapshot(
            scope.get("providerConnectionId"), scope["provider"])
        for scope in scopes
    } == evidence.get("keyedProviderCredentialSnapshots")


def _assert_reviewable_sketch_schema(engagement: Any, revision: Mapping[str, Any]) -> None:
    if engagement is None:
        raise CoreDeploymentPlanError(["engagement not found"])
    from app.services.engagements import _validate_sketch_schema

    errors: list[str] = []
    parameters = revision.get("inputParameters") or {}
    _validate_sketch_schema(getattr(engagement, "sketch_state_schema", "split-v1"), parameters, errors)
    if errors:
        raise CoreDeploymentPlanError(errors)


def _safe_sources(root: Path) -> list[dict[str, str]]:
    result = []
    for name in SAFE_TERRAFORM_SOURCE_FILES:
        path = root / name
        if path.is_file():
            result.append({"path": name, "content": path.read_text(encoding="utf-8")[:200_000]})
    return result


def _terraform_loadable_root_name(name: str) -> bool:
    return (
        name.endswith(".tf") or name.endswith(".tf.json")
        or name.startswith("terraform.tfvars")
        or name.endswith(".auto.tfvars") or name.endswith(".auto.tfvars.json")
    )


def build_keyed_core_terraform_source_manifest(root: Path) -> dict[str, Any]:
    """Seal only Terraform root inputs, without persisting their sensitive contents."""
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("root is not a regular directory")
        entries = {entry.name: entry for entry in root.iterdir()}
        expected = set(KEYED_CORE_TERRAFORM_INPUT_FILES)
        extras = sorted(name for name in entries if _terraform_loadable_root_name(name) and name not in expected)
        if extras or not expected.issubset(entries):
            raise ValueError("Terraform root inputs differ from the reviewed allowlist")
        digests: dict[str, str] = {}
        for name in KEYED_CORE_TERRAFORM_INPUT_FILES:
            path = entries[name]
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("Terraform root input is not a regular file")
            digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, ValueError) as exc:
        raise CoreDeploymentPlanError(["keyed core Terraform source inputs are missing or unsafe"]) from exc
    return {"schema": KEYED_CORE_TERRAFORM_INPUT_SCHEMA, "sha256": digests}


def require_keyed_core_terraform_source_manifest(root: Path, manifest: Any) -> None:
    """Validate an exact, private source seal for original apply or future destroy preview."""
    if not isinstance(manifest, Mapping) or set(manifest) != {"schema", "sha256"}:
        raise CoreDeploymentPlanError(["keyed core Terraform source manifest is missing or invalid"])
    hashes = manifest.get("sha256")
    if (manifest.get("schema") != KEYED_CORE_TERRAFORM_INPUT_SCHEMA or not isinstance(hashes, Mapping)
            or set(hashes) != set(KEYED_CORE_TERRAFORM_INPUT_FILES)
            or any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in hashes.values())):
        raise CoreDeploymentPlanError(["keyed core Terraform source manifest is missing or invalid"])
    if build_keyed_core_terraform_source_manifest(root) != manifest:
        raise CoreDeploymentPlanError(["keyed core Terraform source inputs changed since review"])


def _safe_cidrs(value: Any) -> list[str]:
    values = value if isinstance(value, list) else []
    result: list[str] = []
    for item in values:
        raw = str(item).strip()
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise CoreDeploymentPlanError([f"invalid trusted SSH CIDR: {raw}"]) from exc
        if str(network) == "0.0.0.0/0":
            raise CoreDeploymentPlanError(["sshSourceCidrs must not include 0.0.0.0/0"])
        normalized = str(network)
        if normalized not in result:
            result.append(normalized)
    return result


def _invalidate_if_configuration_changed(
    plan: DeploymentPlan | None, repository: DeploymentPlanRepository
) -> DeploymentPlan | None:
    if plan is None or plan.status not in {"ready", "no_changes", "failed"} or not plan.evidence:
        return plan
    evidence = plan.evidence
    engagement = get_engagement(plan.engagement_id)
    current_revision = get_revision(plan.revision_id)
    from app.storage.engagement_workspace_repository import SqlAlchemyEngagementWorkspaceRepository

    workspace = SqlAlchemyEngagementWorkspaceRepository().get(plan.engagement_id)
    target_changed = False
    if engagement is not None:
        from app.services.guarded_test_deployment import _target_for_engagement

        target = _target_for_engagement(engagement)
        target_changed = _json_hash(
            {"name": target.name, "region": target.region, "compartmentId": target.compartment_id}
        ) != evidence.get("targetFingerprint")
    sketch_changed = False
    keyed_authorization_changed = False
    keyed_credential_changed = False
    try:
        _assert_reviewable_sketch_schema(engagement, current_revision or {})
        _scope, _ids, sketch_fingerprint, _fingerprints = _reviewed_post_core_scope(
            plan.engagement_id, current_revision or {}
        )
        sketch_changed = sketch_fingerprint != evidence.get("sketchIntentFingerprint")
        if evidence.get("sketchStateSchema") == "provider-keyed-v2":
            keyed_authorization_changed = (
                _reviewed_keyed_sketch_authorization(
                    plan.engagement_id, _scope, _fingerprints,
                    evidence.get("digitaloceanImage"), evidence.get("linodeImage")
                ) != evidence.get("sketchAuthorization")
                or (plan.review.get("reviewedConfiguration") or {}).get("sketchAuthorization") != evidence.get("sketchAuthorization")
            )
            keyed_credential_changed = not _reviewed_keyed_credentials_match(evidence)
    except (CoreDeploymentPlanError, ValueError):
        sketch_changed = True
    profile_changed = False
    try:
        template_id = str((current_revision or {}).get("templateId") or (engagement.template_id if engagement else "") or "standard-rti")
        current_profile = resolve_oci_compute_profile(template_id)
        profile_changed = (
            current_profile.fingerprint != evidence.get("computeProfileFingerprint")
            or current_profile.to_dict() != evidence.get("computeProfileSnapshot")
        )
    except Exception:
        profile_changed = True
    keyed_image_changed = not _reviewed_keyed_image_matches(evidence)
    changed = (
        engagement is None
        or engagement.active_revision != plan.revision_id
        or _json_hash(current_revision) != evidence.get("revisionFingerprint")
        or workspace is None
        or _json_hash(workspace.metadata) != evidence.get("capabilitySelectionFingerprint")
        or target_changed
        or sketch_changed
        or keyed_authorization_changed
        or keyed_credential_changed
        or (engagement is not None and getattr(engagement, "sketch_state_schema", "split-v1") != evidence.get("sketchStateSchema", "split-v1"))
        or keyed_image_changed
        or profile_changed
        or evidence.get("ociCoreInstanceBaselineFingerprint") != OCI_CORE_INSTANCE_BASELINE_FINGERPRINT
    )
    if not changed:
        return plan
    invalidated = repository.save(replace(plan, status="invalidated", stage="invalidated", error="deployment configuration changed; prepare a new plan"))
    _cleanup_unapplied_plan_artifacts(plan)
    return invalidated


def _reviewed_keyed_image_matches(evidence: Mapping[str, Any]) -> bool:
    if evidence.get("sketchStateSchema") != "provider-keyed-v2":
        return True
    image = evidence.get("digitaloceanImage")
    if not isinstance(image, str) or not image:
        return False
    try:
        profile = managed_host_image_profile_named(
            str(evidence.get("managedHostImageProfile") or ""))
        if profile.digitalocean_image != image:
            return False
        authorization = evidence.get("sketchAuthorization")
        if isinstance(authorization, Mapping) and authorization.get("kind") == "bounded-mixed-post-core-v1":
            return profile.linode_image == evidence.get("linodeImage")
        return "linodeImage" not in evidence
    except Exception:
        return False


def _cleanup_saved_plan_binary(plan: DeploymentPlan) -> None:
    evidence = plan.evidence
    run_directory = Path(str(evidence.get("runDirectory") or ""))
    plan_path = Path(str(evidence.get("planPath") or ""))
    if plan_path.name == PLAN_FILENAME and plan_path.parent == run_directory and plan_path.is_file() and not plan_path.is_symlink():
        plan_path.unlink(missing_ok=True)


def _cleanup_unapplied_plan_artifacts(plan: DeploymentPlan) -> None:
    _cleanup_saved_plan_binary(plan)
    evidence = plan.evidence
    data_dir = Path(str(evidence.get("terraformDataDir") or ""))
    state_path = Path(str(evidence.get("terraformStatePath") or ""))
    # The data directory is a sibling of the persistent state and has a
    # generated data-core-* name. Never remove the shared state itself.
    if data_dir.name.startswith("data-core-") and data_dir.parent == state_path.parent and data_dir.is_dir() and not data_dir.is_symlink():
        import shutil

        shutil.rmtree(data_dir)


def _run_command(command: list[str], cwd: Path, env: Mapping[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=dict(env), check=False, capture_output=True, text=True)


def _checked(result: subprocess.CompletedProcess[str], label: str) -> subprocess.CompletedProcess[str]:
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed")
    return result


def _file_hash(path: Path) -> str:
    if not str(path) or not path.is_file() or path.is_symlink():
        return "absent"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_hash(root: Path, exclude: set[str] | None = None) -> str:
    if not str(root) or not root.is_dir():
        return "absent"
    digest = hashlib.sha256()
    excluded = exclude or set()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        if path.name in excluded or ".terraform" in path.parts or path.name.endswith(".log"):
            continue
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _json_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _terraform_version(terraform: str, cwd: Path, env: Mapping[str, str], run: CommandRunner) -> str:
    result = _checked(run([terraform, "version", "-json"], cwd, env), "terraform version")
    try:
        return str(json.loads(result.stdout).get("terraform_version") or "")
    except json.JSONDecodeError:
        raise RuntimeError("terraform version output was invalid")


def _safe_error(exc: Exception) -> str:
    if isinstance(exc, CoreDeploymentPlanError):
        return "; ".join(exc.errors)
    return f"{type(exc).__name__}: plan preparation failed"


def _start_background(task: Callable[[], None]) -> None:
    start_runtime_task(task, name="barragan-core-plan-preparer", synchronous_when_testing=True)
