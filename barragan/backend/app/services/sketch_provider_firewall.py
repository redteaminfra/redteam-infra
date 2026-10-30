# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable

from app.integrations.terraform_runner import LocalTerraformCommandRunner, TerraformCommandRunner
from app.services.terraform_plan_gate import (
    FirewallIngressDelta,
    FirewallIngressPort,
    TerraformPlanGateError,
    require_provider_firewall_ingress_update,
)
from app.services.credentials import resolve_credential_secret
from app.services.engagements import get_engagement
from app.services.digitalocean_sketch_deployment import (
    DIGITALOCEAN_TOKEN_ENV_VAR,
    _provider_name_slug as digitalocean_provider_name_slug,
    _resource_name_suffix as digitalocean_resource_name_suffix,
)
from app.services.linode_sketch_deployment import (
    LINODE_TOKEN_ENV_VAR,
    _provider_name_slug as linode_provider_name_slug,
    _resource_name_suffix as linode_resource_name_suffix,
)
from app.services.redteam_infra_template import redteam_infra_sketch_template_dir
from app.services.sketch_state_workspaces import (
    grant_collaborator_access_to_existing_sketch_state_workspace,
    MaterializedSketchKeys,
    materialized_sketch_key_files,
    retained_compute_image_for_workspace,
    validate_existing_sketch_state_workspace,
)
from app.services.template_compatibility import (
    ensure_linode_firewall_protocol_compatibility,
    ensure_sketch_firewall_port_list_compatibility,
    ensure_sketch_udp_ingress_compatibility,
    ensure_sketch_resource_name_suffix_compatibility,
    ensure_sketch_ssh_variable_contract_compatibility,
    stabilize_digitalocean_ssh_key_ownership,
)
from app.storage.credential_repository import CredentialRepository
from app.storage.job_repository import JobRepository, SqlAlchemyJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import (
    SketchChainRepository,
    SqlAlchemySketchChainRepository,
    StoredSketchChain,
)


DEFAULT_PROVIDER_TCP_INGRESS_PORTS = (22, 80, 443, 2222)
DEFAULT_PROVIDER_UDP_INGRESS_PORTS: tuple[int, ...] = ()
ACTIVE_PROVIDER_INGRESS_CHANNEL_STATUSES = {
    "pending apply",
    "pending validation",
    "validated",
    "validation failed",
}
SUPPORTED_PROVIDERS = {"linode", "digitalocean"}
PROVIDER_FIREWALL_TARGETS = {
    "linode": ("linode_firewall.firewall",),
    "digitalocean": ("digitalocean_firewall.firewall",),
}
MAX_TERRAFORM_OUTPUT_CHARS = 3000

CredentialResolver = Callable[[str, str, CredentialRepository | None], str]


class DurableSketchKeyRecoveryError(ValueError):
    """A retained Terraform workspace cannot recover its established SSH identity."""


@dataclass(frozen=True)
class ProviderIngressSyncEvent:
    level: str
    message: str
    data: dict[str, Any]


@dataclass(frozen=True)
class ProviderIngressPlan:
    chain_id: str
    operation: str
    channel_id: str
    channel_protocol: str
    channel_external_port: int
    allowed_tcp_ports: tuple[int, ...]
    allowed_udp_ports: tuple[int, ...]
    active_channel_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chainId": self.chain_id,
            "operation": self.operation,
            "channelId": self.channel_id,
            "channelProtocol": self.channel_protocol,
            "channelExternalPort": self.channel_external_port,
            "allowedTcpPorts": [str(port) for port in self.allowed_tcp_ports],
            "allowedUdpPorts": [str(port) for port in self.allowed_udp_ports],
            "activeChannelIds": list(self.active_channel_ids),
        }


@dataclass(frozen=True)
class ProviderIngressSyncResult:
    status: str
    ok: bool
    provider: str
    chain_id: str
    events: tuple[ProviderIngressSyncEvent, ...]
    plan: ProviderIngressPlan | None = None


@dataclass
class _SourceSnapshot:
    workspace: Path
    files: dict[Path, bytes]

    @classmethod
    def capture(cls, workspace: Path) -> _SourceSnapshot:
        return cls(
            workspace=workspace,
            files={
                path.relative_to(workspace): path.read_bytes()
                for path in workspace.rglob("*.tf")
                if path.is_file() and not path.is_symlink()
            },
        )

    def restore(self) -> None:
        current = {
            path.relative_to(self.workspace): path
            for path in self.workspace.rglob("*.tf")
            if path.is_file() and not path.is_symlink()
        }
        for relative, path in current.items():
            if relative not in self.files:
                path.unlink()
        for relative, content in self.files.items():
            path = self.workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


@dataclass
class _PreparedProviderReconciliation:
    provider: str
    role: str
    workspace: Path
    component_id: str | None
    retained_image: str
    alias: str
    env: dict[str, str]
    variables: dict[str, Any]
    key_paths: tuple[Path, ...]
    plan: ProviderIngressPlan
    refreshed_files: list[str]
    ssh_key_ownership: str
    snapshot: _SourceSnapshot
    plan_path: Path | None = None
    plan_identity: tuple[Any, ...] | None = None
    start: ProviderIngressSyncEvent | None = None
    changes: list[Any] | None = None
    apply_started: bool = False


@dataclass(frozen=True)
class _ValidatedProviderWorkspace:
    provider: str
    role: str
    provider_input: dict[str, Any]
    workspace: Path
    component_id: str | None
    retained_image: str
    plan: ProviderIngressPlan


def provider_ingress_preflight_errors(
    engagement_id: str,
    chain_id: str,
    *,
    job_repository: JobRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
) -> list[str]:
    """Read-only readiness checks required before a channel batch mutates."""
    engagement = get_engagement(engagement_id)
    if engagement is not None and engagement.sketch_state_schema == "provider-keyed-v2":
        try:
            from app.services.provider_keyed_channel_apply import load_keyed_channel_source
            source, *_ = load_keyed_channel_source(engagement_id, job_repository or SqlAlchemyJobRepository(),
                                                   sketches=chain_repository)
            return [] if chain_id in source.chain_ids else ["selected keyed chain is outside the published generation"]
        except Exception:
            return ["keyed channel Apply requires a current published six-node generation"]
    if engagement is None or engagement.sketch_state_schema != "split-v1":
        return ["managed provider ingress requires an existing split-v1 engagement"]
    chain_repo = chain_repository or SqlAlchemySketchChainRepository()
    job_repo = job_repository or SqlAlchemyJobRepository()
    chain = chain_repo.get(engagement_id, chain_id)
    if chain is None:
        return [f"sketch chain {chain_id} was not found"]
    errors: list[str] = []
    if chain.status != "deployed":
        errors.append(f"sketch chain {chain_id} is {chain.status or 'not ready'}; provider ingress requires a deployed chain")
    deploy_job = job_repo.get(chain.deploy_job_id) if chain.deploy_job_id else None
    if deploy_job is None:
        errors.append(f"sketch chain {chain_id} does not have its deploy job evidence")
        return errors
    for role, provider in (("middle", _normalize_provider(chain.middle_provider)), ("edge", _normalize_provider(chain.edge_provider))):
        if provider not in SUPPORTED_PROVIDERS:
            errors.append(f"{role} provider {provider or 'unknown'} is not supported for managed ingress")
            continue
        provider_input = _provider_input(provider, deploy_job, provider_role=role)
        try:
            _credential_alias(provider, provider_input)
        except ValueError as exc:
            errors.append(str(exc))
        workspace_text = (
            _input_text(provider_input, "terraformWorkingDirectory")
            if role == "middle"
            else _text(chain.terraform_working_directory) or _input_text(provider_input, "terraformWorkingDirectory")
        )
        if not workspace_text:
            errors.append(f"{role} provider workspace is unavailable for sketch chain {chain_id}")
            continue
        try:
            validate_existing_sketch_state_workspace(
                engagement_id,
                chain_id,
                provider,
                Path(workspace_text),
                component_id=_input_text(provider_input, "componentId") or None,
            )
        except ValueError as exc:
            errors.append(f"{role} provider workspace is not eligible for managed ingress: {exc}")
    return list(dict.fromkeys(errors))


def sync_provider_ingress_for_inbound_channel(
    engagement_id: str,
    engagement_name: str,
    chain_id: str,
    *,
    operation: str,
    channel: dict[str, Any],
    overview: dict[str, Any] | None,
    job_repository: JobRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    credential_resolver: CredentialResolver | None = None,
    terraform_runner: TerraformCommandRunner | None = None,
) -> ProviderIngressSyncResult:
    base_plan = provider_ingress_plan(overview or {}, chain_id, operation=operation, channel=channel)
    engagement = get_engagement(engagement_id)
    if engagement is None or engagement.sketch_state_schema != "split-v1":
        return _failed("", chain_id, base_plan, "sketch provider ingress sync failed", {
            "reason": "invalid_sketch_state_schema",
            "detail": "Managed provider ingress requires an existing split-v1 engagement.",
        })
    chain_repo = chain_repository or SqlAlchemySketchChainRepository()
    job_repo = job_repository or SqlAlchemyJobRepository()
    chain = chain_repo.get(engagement_id, chain_id)
    if chain is None:
        return _failed("", chain_id, base_plan, "sketch provider ingress sync failed", {
            "reason": "sketch_chain_not_found",
            "detail": f"Sketch chain {chain_id} was not found; provider ingress was not changed.",
        })
    deploy_job = job_repo.get(chain.deploy_job_id) if chain.deploy_job_id else None
    if deploy_job is None:
        return _failed("", chain_id, base_plan, "sketch provider ingress sync failed", {
            "reason": "missing_deploy_job",
            "detail": "The sketch deploy job could not be found; provider credential alias and Terraform inputs are unavailable.",
        })

    edge_provider = _normalize_provider(chain.edge_provider)
    roles = [("edge", edge_provider)]
    middle_provider = _normalize_provider(chain.middle_provider)
    if middle_provider != edge_provider:
        roles.append(("middle", middle_provider))
    unsupported = [provider for _, provider in roles if provider not in SUPPORTED_PROVIDERS]
    if unsupported:
        return _skipped(unsupported[0], chain_id, base_plan, "sketch provider ingress sync skipped", {
            "reason": "unsupported_provider",
            "detail": f"Provider ingress sync is not implemented for {unsupported[0] or 'unknown provider'}.",
        })

    runner = terraform_runner or LocalTerraformCommandRunner()
    resolver = credential_resolver or resolve_credential_secret
    prepared: list[_PreparedProviderReconciliation] = []
    snapshots: list[_SourceSnapshot] = []
    try:
        with ExitStack() as stack:
            validated_roles: list[_ValidatedProviderWorkspace] = []
            # Establish provenance and immutable compute identity for every
            # provider half before adapting even the first workspace.
            for role, provider in roles:
                provider_input = _provider_input(provider, deploy_job, provider_role=role)
                workspace_text = (
                    (_text(chain.terraform_working_directory) if role == "edge" else "")
                    or _input_text(provider_input, "terraformWorkingDirectory")
                )
                if not workspace_text:
                    raise ValueError(f"{role} provider Terraform workspace is missing")
                component_id = _input_text(provider_input, "componentId") or None

                # Provenance and the retained image are established before the
                # workspace, keys, credentials, or Terraform are touched.
                workspace = validate_existing_sketch_state_workspace(
                    engagement_id, chain_id, provider, Path(workspace_text), component_id=component_id
                ).path
                retained_image = retained_compute_image_for_workspace(
                    engagement_id, chain_id, provider, workspace, component_id=component_id
                )
                validated_roles.append(_ValidatedProviderWorkspace(
                    provider=provider,
                    role=role,
                    provider_input=provider_input,
                    workspace=workspace,
                    component_id=component_id,
                    retained_image=retained_image,
                    plan=provider_ingress_plan(
                        overview or {}, chain_id, operation=operation, channel=channel,
                        port_field="relayPort" if role == "middle" else "externalPort",
                    ),
                ))

            for validated_role in validated_roles:
                grant_collaborator_access_to_existing_sketch_state_workspace(
                    engagement_id,
                    chain_id,
                    validated_role.provider,
                    validated_role.workspace,
                    component_id=validated_role.component_id,
                )

            materialized_keys: MaterializedSketchKeys | None = None
            if any(
                _selected_input_requests_key_materialization(deploy_job, role.provider_input)
                for role in validated_roles
            ):
                try:
                    materialized_keys = stack.enter_context(
                        materialized_sketch_key_files(engagement_id)
                    )
                except Exception as exc:
                    raise DurableSketchKeyRecoveryError(
                        "the engagement's durable sketch SSH identities are unavailable"
                    ) from exc

            for validated_role in validated_roles:
                provider = validated_role.provider
                role = validated_role.role
                provider_input = validated_role.provider_input
                workspace = validated_role.workspace
                component_id = validated_role.component_id
                retained_image = validated_role.retained_image
                snapshot = _SourceSnapshot.capture(workspace)
                snapshots.append(snapshot)
                refreshed_files = _refresh_provider_firewall_templates(provider, workspace)
                ensure_sketch_resource_name_suffix_compatibility(workspace, provider)
                ensure_sketch_udp_ingress_compatibility(workspace, provider)
                ensure_sketch_ssh_variable_contract_compatibility(workspace, provider)
                ensure_linode_firewall_protocol_compatibility(workspace, provider)
                ensure_sketch_firewall_port_list_compatibility(workspace, provider)
                ssh_key_ownership = (
                    stabilize_digitalocean_ssh_key_ownership(workspace)
                    if provider == "digitalocean" else "not_applicable"
                )
                ownership_tags = _preserve_retained_firewall_ownership(workspace, provider)
                effective_input = _provider_input_with_materialized_keys(
                    provider_input,
                    materialized_keys
                    if _selected_input_requests_key_materialization(deploy_job, provider_input)
                    else None,
                )
                role_plan = validated_role.plan
                variables = _terraform_variables(
                    provider, engagement_name, chain, effective_input, role_plan, workspace,
                    ownership_tags=ownership_tags, retained_image=retained_image,
                )
                key_paths = _declared_key_paths(variables)
                _require_live_key_paths(key_paths)
                alias = _credential_alias(provider, effective_input)
                item = _PreparedProviderReconciliation(
                    provider=provider,
                    role=role,
                    workspace=workspace,
                    component_id=component_id,
                    retained_image=retained_image,
                    alias=alias,
                    env={},
                    variables=variables,
                    key_paths=key_paths,
                    plan=role_plan,
                    refreshed_files=refreshed_files,
                    ssh_key_ownership=ssh_key_ownership,
                    snapshot=snapshot,
                )
                prepared.append(item)

            # Validate every component's key contract before resolving either
            # provider credential or invoking Terraform for the transaction.
            for item in prepared:
                item.env = _execution_env(
                    item.provider, item.alias, credential_repository, resolver
                )
            for item in prepared:
                failure = _prepare_provider_firewall_reconciliation(
                    engagement_id, chain_id, operation, item, runner
                )
                if failure is not None:
                    return failure

            # Close the planning/apply queue window for both halves before
            # beginning either irreversible command.
            for item in prepared:
                _revalidate_prepared_workspace(engagement_id, chain_id, item)
            events: list[ProviderIngressSyncEvent] = []
            for item in prepared:
                try:
                    _require_prepared_apply_identity(engagement_id, chain_id, item)
                except Exception as exc:
                    failure = _terraform_reconciliation_failure(
                        item.start, item.provider, chain_id, operation, item.plan,
                        "sketch provider ingress workspace or saved plan changed before apply",
                        {"reason": str(exc), "errorType": type(exc).__name__},
                    )
                    events.extend(failure.events)
                    return ProviderIngressSyncResult(
                        status="failed", ok=False,
                        provider="+".join(entry.provider for entry in prepared),
                        chain_id=chain_id, plan=base_plan, events=tuple(events),
                    )
                item.apply_started = True
                result = _apply_provider_firewall_reconciliation(
                    engagement_id, chain_id, operation, item, runner
                )
                events.extend(result.events)
                if not result.ok:
                    return ProviderIngressSyncResult(
                        status="failed", ok=False,
                        provider="+".join(entry.provider for entry in prepared),
                        chain_id=chain_id, plan=base_plan, events=tuple(events),
                    )
            return ProviderIngressSyncResult(
                status="synced", ok=True,
                provider="+".join(entry.provider for entry in prepared),
                chain_id=chain_id, plan=base_plan, events=tuple(events),
            )
    except Exception as exc:
        return _failed(
            "+".join(provider for _, provider in roles), chain_id, base_plan,
            "sketch provider ingress sync failed",
            {"reason": "provider_ingress_inputs_unavailable", "errorType": type(exc).__name__},
        )
    finally:
        for item in prepared:
            if item.plan_path is not None:
                item.plan_path.unlink(missing_ok=True)
        started_snapshot_ids = {
            id(item.snapshot) for item in prepared if item.apply_started
        }
        for snapshot in reversed(snapshots):
            if id(snapshot) not in started_snapshot_ids:
                snapshot.restore()

def _prepare_provider_firewall_reconciliation(
    engagement_id: str,
    chain_id: str,
    operation: str,
    item: _PreparedProviderReconciliation,
    runner: TerraformCommandRunner,
) -> ProviderIngressSyncResult | None:
    item.start = ProviderIngressSyncEvent(
        "info", "sketch provider ingress sync started", {
            "provider": item.provider,
            "providerRole": item.role,
            "chainId": chain_id,
            "operation": operation,
            "workspaceDir": str(item.workspace),
            "credentialAlias": item.alias,
            "credentialRef": f"credential://{item.provider}/{item.alias}",
            "templateFilesRefreshed": item.refreshed_files,
            "sshKeyOwnership": item.ssh_key_ownership,
            "ingressPlan": item.plan.to_dict(),
        },
    )
    try:
        _revalidate_prepared_workspace(engagement_id, chain_id, item)
        _require_live_key_paths(item.key_paths)
        init_result = runner.run("init", working_directory=str(item.workspace), env=item.env, variables={})
        if init_result.returncode != 0:
            return ProviderIngressSyncResult(
                status="failed", ok=False, provider=item.provider, chain_id=chain_id, plan=item.plan,
                events=(item.start, ProviderIngressSyncEvent(
                    "error", "sketch provider ingress terraform init failed", {
                        "provider": item.provider, "chainId": chain_id, "operation": operation,
                        "commandResult": _safe_terraform_result(
                            init_result, sensitive_key_paths=item.key_paths
                        ),
                        "ingressPlan": item.plan.to_dict(),
                    },
                )),
            )
        plan_fd, plan_path_text = tempfile.mkstemp(
            dir=item.workspace, prefix=".barragan-provider-firewall-", suffix=".tfplan"
        )
        os.close(plan_fd)
        item.plan_path = Path(plan_path_text)
        item.plan_path.unlink()
        _revalidate_prepared_workspace(engagement_id, chain_id, item)
        _require_live_key_paths(item.key_paths)
        plan_result = runner.run(
            "plan", working_directory=str(item.workspace), env=item.env,
            variables=item.variables, saved_plan_path=item.plan_path,
        )
        if plan_result.returncode not in {0, 2}:
            return _terraform_reconciliation_failure(
                item.start, item.provider, chain_id, operation, item.plan,
                "sketch provider ingress terraform plan failed",
                {"commandResult": _safe_terraform_result(
                    plan_result, sensitive_key_paths=item.key_paths
                )},
            )
        if not item.plan_path.is_file():
            raise TerraformPlanGateError("terraform plan did not create the saved plan artifact")
        os.chmod(item.plan_path, 0o600)
        _revalidate_prepared_workspace(engagement_id, chain_id, item)
        _require_live_key_paths(item.key_paths)
        show_result = runner.run(
            "show", working_directory=str(item.workspace), env=item.env, saved_plan_path=item.plan_path
        )
        if show_result.returncode != 0:
            return _terraform_reconciliation_failure(
                item.start, item.provider, chain_id, operation, item.plan,
                "sketch provider ingress saved plan inspection failed",
                {"commandResult": _safe_terraform_result(
                    show_result, sensitive_key_paths=item.key_paths
                )},
            )
        expected_delta = _expected_ingress_delta(show_result.stdout, item.provider, item.plan)
        item.changes = require_provider_firewall_ingress_update(
            show_result.stdout, provider=item.provider, expected_delta=expected_delta
        )
        item.plan_identity = _file_identity(item.plan_path)
        return None
    except TerraformPlanGateError as exc:
        return _terraform_reconciliation_failure(
            item.start, item.provider, chain_id, operation, item.plan,
            "sketch provider ingress terraform plan rejected", {"reason": str(exc)},
        )


def _apply_provider_firewall_reconciliation(
    engagement_id: str,
    chain_id: str,
    operation: str,
    item: _PreparedProviderReconciliation,
    runner: TerraformCommandRunner,
) -> ProviderIngressSyncResult:
    assert item.start is not None and item.plan_path is not None and item.changes is not None
    _require_live_key_paths(item.key_paths)
    apply_result = runner.run(
        "apply", working_directory=str(item.workspace), env=item.env, saved_plan_path=item.plan_path
    )
    if apply_result.returncode != 0:
        return _terraform_reconciliation_failure(
            item.start, item.provider, chain_id, operation, item.plan,
            "sketch provider ingress terraform apply failed",
            {"commandResult": _safe_terraform_result(
                apply_result, sensitive_key_paths=item.key_paths
            )},
        )
    return ProviderIngressSyncResult(
        status="synced", ok=True, provider=item.provider, chain_id=chain_id, plan=item.plan,
        events=(item.start, ProviderIngressSyncEvent(
            "info", "sketch provider ingress synced", {
                "provider": item.provider, "providerRole": item.role,
                "chainId": chain_id, "operation": operation,
                "commandResult": _safe_terraform_result(
                    apply_result, sensitive_key_paths=item.key_paths
                ),
                "approvedChanges": [
                    {"address": change.address, "action": change.action} for change in item.changes
                ],
                "ingressPlan": item.plan.to_dict(),
            },
        )),
    )


def _revalidate_prepared_workspace(
    engagement_id: str, chain_id: str, item: _PreparedProviderReconciliation
) -> None:
    validated = validate_existing_sketch_state_workspace(
        engagement_id, chain_id, item.provider, item.workspace, component_id=item.component_id
    )
    if validated.path != item.workspace:
        raise ValueError("retained sketch workspace identity changed")
    retained_image = retained_compute_image_for_workspace(
        engagement_id, chain_id, item.provider, item.workspace, component_id=item.component_id
    )
    if retained_image != item.retained_image:
        raise ValueError("retained sketch compute image identity changed")


def _require_prepared_apply_identity(
    engagement_id: str, chain_id: str, item: _PreparedProviderReconciliation
) -> None:
    _revalidate_prepared_workspace(engagement_id, chain_id, item)
    if item.plan_path is None or item.plan_identity is None:
        raise ValueError("inspected Terraform saved plan is unavailable")
    if _file_identity(item.plan_path) != item.plan_identity:
        raise ValueError("inspected Terraform saved plan changed before apply")


def _file_identity(path: Path) -> tuple[Any, ...]:
    stat_result = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_mode,
        stat_result.st_uid,
        stat_result.st_gid,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        digest.hexdigest(),
    )


def _expected_ingress_delta(
    plan_json: str, provider: str, desired: ProviderIngressPlan
) -> FirewallIngressDelta:
    try:
        document = json.loads(plan_json)
    except json.JSONDecodeError as exc:
        raise TerraformPlanGateError("saved Terraform plan was not machine-readable JSON") from exc
    if not isinstance(document, dict):
        raise TerraformPlanGateError("saved Terraform plan emitted an invalid document")
    address = PROVIDER_FIREWALL_TARGETS[provider][0]
    resources = document.get("resource_changes")
    if not isinstance(resources, list):
        raise TerraformPlanGateError("saved Terraform plan omitted resource changes")
    resource = next((entry for entry in resources if isinstance(entry, dict) and entry.get("address") == address), None)
    if resource is None:
        _require_planned_firewall_projection(document, provider, desired)
        return FirewallIngressDelta()
    change = resource.get("change")
    before = change.get("before") if isinstance(change, dict) else None
    if not isinstance(before, dict):
        raise TerraformPlanGateError("saved Terraform firewall change omitted before semantics")
    current = _public_ingress_ports(provider, before)
    wanted = {
        *(FirewallIngressPort("tcp", port) for port in desired.allowed_tcp_ports),
        *(FirewallIngressPort("udp", port) for port in desired.allowed_udp_ports),
    }
    actions = change.get("actions") if isinstance(change, dict) else None
    if actions == ["no-op"]:
        if current != wanted:
            raise TerraformPlanGateError(
                "no-change Terraform plan does not prove the exact desired provider ingress projection"
            )
        return FirewallIngressDelta()
    # Drift repair may restore any desired non-SSH listener. Removals are
    # restricted to the candidate listener for an explicit remove operation,
    # so an unrelated sibling rule can never be erased by this transaction.
    added = frozenset(port for port in wanted - current if not (port.protocol == "tcp" and port.port == 22))
    removable = set()
    if desired.operation == "remove" and desired.channel_external_port:
        removable.add(FirewallIngressPort(desired.channel_protocol, desired.channel_external_port))
    removed = frozenset((current - wanted) & removable)
    return FirewallIngressDelta(added=added, removed=removed)


def _require_planned_firewall_projection(
    document: dict[str, Any], provider: str, desired: ProviderIngressPlan
) -> None:
    planned_values = document.get("planned_values")
    root_module = planned_values.get("root_module") if isinstance(planned_values, dict) else None
    if not isinstance(root_module, dict):
        raise TerraformPlanGateError(
            "no-change Terraform plan omitted the planned provider firewall projection"
        )
    address = PROVIDER_FIREWALL_TARGETS[provider][0]
    planned_resource = next(
        (resource for resource in _planned_module_resources(root_module) if resource.get("address") == address),
        None,
    )
    values = planned_resource.get("values") if isinstance(planned_resource, dict) else None
    if not isinstance(values, dict):
        raise TerraformPlanGateError(
            "no-change Terraform plan omitted the planned provider firewall projection"
        )
    actual = _public_ingress_ports(provider, values)
    expected = {
        *(FirewallIngressPort("tcp", port) for port in desired.allowed_tcp_ports),
        *(FirewallIngressPort("udp", port) for port in desired.allowed_udp_ports),
    }
    if actual != expected:
        raise TerraformPlanGateError(
            "no-change Terraform plan does not prove the exact desired provider ingress projection"
        )


def _planned_module_resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    resources = [resource for resource in module.get("resources", []) if isinstance(resource, dict)]
    for child in module.get("child_modules", []):
        if isinstance(child, dict):
            resources.extend(_planned_module_resources(child))
    return resources


def _public_ingress_ports(provider: str, firewall: dict[str, Any]) -> set[FirewallIngressPort]:
    attribute = "inbound" if provider == "linode" else "inbound_rule"
    rules = firewall.get(attribute)
    if not isinstance(rules, list):
        raise TerraformPlanGateError("saved Terraform firewall change omitted provider ingress rules")
    ports: set[FirewallIngressPort] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise TerraformPlanGateError("saved Terraform firewall change emitted an invalid ingress rule")
        if provider == "linode":
            if rule.get("action") != "ACCEPT" or rule.get("ipv4") != ["0.0.0.0/0"]:
                continue
            protocol = str(rule.get("protocol") or "").lower()
            raw_port = rule.get("ports")
        else:
            if rule.get("source_addresses") != ["0.0.0.0/0"]:
                continue
            protocol = str(rule.get("protocol") or "").lower()
            raw_port = rule.get("port_range")
        try:
            port = int(str(raw_port))
        except (TypeError, ValueError):
            if protocol in {"tcp", "udp"}:
                raise TerraformPlanGateError(
                    "provider firewall contains a public TCP/UDP rule that is not one exact port"
                )
            continue
        if protocol in {"tcp", "udp"} and 1 <= port <= 65535:
            ports.add(FirewallIngressPort(protocol, port))
    return ports

def _terraform_reconciliation_failure(
    start: ProviderIngressSyncEvent,
    provider: str,
    chain_id: str,
    operation: str,
    plan: ProviderIngressPlan,
    message: str,
    data: dict[str, Any],
) -> ProviderIngressSyncResult:
    return ProviderIngressSyncResult(
        status="failed",
        ok=False,
        provider=provider,
        chain_id=chain_id,
        plan=plan,
        events=(
            start,
            ProviderIngressSyncEvent(
                "info",
                "sketch provider ingress terraform init succeeded",
                {"provider": provider, "chainId": chain_id, "operation": operation},
            ),
            ProviderIngressSyncEvent(
                "error",
                message,
                {
                    "provider": provider,
                    "chainId": chain_id,
                    "operation": operation,
                    "ingressPlan": plan.to_dict(),
                    **data,
                },
            ),
        ),
    )


def _provider_input_with_materialized_keys(
    provider_input: dict[str, Any], materialized_keys: MaterializedSketchKeys | None
) -> dict[str, Any]:
    if materialized_keys is None:
        return provider_input
    return {
        **provider_input,
        "sshPrivateKeyPath": materialized_keys.administration_private_key_path,
        "sshPublicKeyPath": materialized_keys.administration_public_key_path,
        "infrastructureAdminSshPrivateKeyPath": materialized_keys.administration_private_key_path,
        "infrastructureAdminSshPublicKeyPath": materialized_keys.administration_public_key_path,
        "sketchTransportSshPublicKeyPath": materialized_keys.transport_public_key_path,
    }


def _selected_input_requests_key_materialization(
    deploy_job: StoredJobRun, provider_input: dict[str, Any]
) -> bool:
    """Use a mixed component's marker; retain the parent marker for legacy same-provider jobs."""

    if provider_input is deploy_job.input:
        return deploy_job.input.get("materializeKeyFiles") is True
    return provider_input.get("materializeKeyFiles") is True


def _declared_key_paths(variables: dict[str, Any]) -> tuple[Path, ...]:
    names = (
        "infrastructure_admin_ssh_pub_key_path",
        "infrastructure_admin_ssh_priv_key_path",
        "sketch_transport_ssh_pub_key_path",
        "ssh_pub_key_path",
        "ssh_priv_key_path",
    )
    return tuple(Path(str(variables[name])) for name in names if name in variables)


def _require_live_key_paths(paths: tuple[Path, ...]) -> None:
    if any(not path.is_file() for path in paths):
        raise DurableSketchKeyRecoveryError(
            "retained Terraform key files are unavailable; recover the engagement's durable sketch identity before retrying"
        )


def sync_provider_ingress_for_transport(
    engagement_id: str,
    engagement_name: str,
    chain_id: str,
    *,
    overview: dict[str, Any] | None,
    job_repository: JobRepository | None = None,
    chain_repository: SketchChainRepository | None = None,
    credential_repository: CredentialRepository | None = None,
    credential_resolver: CredentialResolver | None = None,
    terraform_runner: TerraformCommandRunner | None = None,
) -> ProviderIngressSyncResult:
    """Reconcile a chain's retained firewall before a managed transport apply.

    This deliberately uses the same provider-ingress projection as inbound
    channels, but has no candidate listener.  It therefore preserves the
    stock upstream SSH/HTTP port set and any already-active inbound routes;
    it does not invent a transport-specific public port or firewall policy.
    """

    engagement = get_engagement(engagement_id)
    if getattr(engagement, "sketch_state_schema", None) == "provider-keyed-v2":
        try:
            from types import SimpleNamespace
            from app.services.provider_keyed_channel_apply import _prove_provider_generation
            from app.services.provider_keyed_mixed_published_teardown_authority import published_review_policy
            from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id
            from app.storage.credential_repository import SqlAlchemyCredentialRepository
            jobs = job_repository or SqlAlchemyJobRepository()
            sketches = chain_repository or SqlAlchemySketchChainRepository()
            before = tuple(jobs.list_for_engagement(engagement_id))
            chains = tuple(sketches.list_for_engagement(engagement_id))
            from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
            lease = _db_lease_lookup(engagement_id)
            if lease is not None:
                raise ValueError("keyed transport requires an idle engagement")
            retained_states = {}
            def fence():
                if (tuple(jobs.list_for_engagement(engagement_id)) != before
                        or tuple(sketches.list_for_engagement(engagement_id)) != chains
                        or _db_lease_lookup(engagement_id) != lease):
                    raise ValueError("keyed transport source changed")
                from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
                if any(hashlib.sha256(_read(path, private=False)).hexdigest() != digest
                       for path, digest in retained_states.items()):
                    raise ValueError("keyed transport retained state changed")
                return "keyed-transport-read-only"
            collection = _keyed_transport_publication(engagement_id, jobs, sketches)
            if chain_id not in collection.review.source.chain_ids:
                raise ValueError("keyed transport chain differs")
            initial = jobs.get(_parent_id(collection.review.source.core_job_id))
            retained_states.update({Path(path) / "terraform.tfstate":
                collection.observations[provider].classification.state_sha256
                for provider, path in collection.workspaces.items()})
            credentials = credential_repository or SqlAlchemyCredentialRepository()
            for provider, path in collection.workspaces.items():
                fence()
                policy = published_review_policy(collection.review, initial, provider)
                _prove_provider_generation(provider, policy,
                    SimpleNamespace(state_path=Path(path) / "terraform.tfstate"), credentials, fence)
            fence()
            return ProviderIngressSyncResult("verified", True, "mixed", chain_id, (
                ProviderIngressSyncEvent("info", "keyed retained provider firewall verified",
                    {"chainId": chain_id, "mutation": False}),))
        except Exception:
            return ProviderIngressSyncResult("attention", False, "mixed", chain_id, (
                ProviderIngressSyncEvent("error", "keyed transport requires current published provider proof", {}),))
    return sync_provider_ingress_for_inbound_channel(
        engagement_id,
        engagement_name,
        chain_id,
        operation="transport",
        channel={},
        overview=overview,
        job_repository=job_repository,
        chain_repository=chain_repository,
        credential_repository=credential_repository,
        credential_resolver=credential_resolver,
        terraform_runner=terraform_runner,
    )


def _keyed_transport_publication(engagement_id, jobs, sketches):
    """Read-only publication review; never a teardown or ingress write permit."""
    from app.core.runtime import runtime_value
    from app.services.core_ssh import active_core_connection_details
    from app.services.provider_keyed_mixed_published_teardown_collector import collect_published_mixed_initial_teardown
    if runtime_value("ENVIRONMENT") != "devtest":
        raise ValueError("keyed transport is DevTest-only")
    core_id = active_core_connection_details(jobs, engagement_id)[0]
    return collect_published_mixed_initial_teardown(engagement_id, core_id,
        job_repository=jobs, sketch_repository=sketches, read_only_transport=True)


def provider_ingress_plan(
    overview: dict[str, Any],
    chain_id: str,
    *,
    operation: str,
    channel: dict[str, Any],
    port_field: str = "externalPort",
) -> ProviderIngressPlan:
    channel_id = _text(channel.get("channelId"))
    protocol = _channel_protocol(channel)
    # A transport reconciliation has no candidate public listener.  Keep the
    # field shape stable for job evidence while deriving firewall ports solely
    # from the existing active-channel projection below.
    external_port = (
        0
        if operation == "transport"
        else _port(channel.get(port_field) or channel.get("externalPort"))
    )
    removed_channel_id = channel_id if operation == "remove" else ""
    active_channels = _active_channels_for_chain(overview, chain_id, candidate_channel=channel, removed_channel_id=removed_channel_id)
    tcp_ports = set(DEFAULT_PROVIDER_TCP_INGRESS_PORTS)
    udp_ports = set(DEFAULT_PROVIDER_UDP_INGRESS_PORTS)
    active_channel_ids: list[str] = []
    for active_channel in active_channels:
        active_channel_ids.append(_text(active_channel.get("channelId")))
        active_protocol = _channel_protocol(active_channel)
        active_port = _port(active_channel.get(port_field) or active_channel.get("externalPort"))
        if active_protocol == "udp":
            udp_ports.add(active_port)
        else:
            tcp_ports.add(active_port)
    return ProviderIngressPlan(
        chain_id=chain_id,
        operation=operation,
        channel_id=channel_id,
        channel_protocol=protocol,
        channel_external_port=external_port,
        allowed_tcp_ports=tuple(sorted(tcp_ports)),
        allowed_udp_ports=tuple(sorted(udp_ports)),
        active_channel_ids=tuple(channel_id for channel_id in active_channel_ids if channel_id),
    )


def _active_channels_for_chain(
    overview: dict[str, Any],
    chain_id: str,
    *,
    candidate_channel: dict[str, Any],
    removed_channel_id: str,
) -> list[dict[str, Any]]:
    channels = [dict(channel) for channel in overview.get("inboundChannels", []) if isinstance(channel, dict)]
    candidate_id = _text(candidate_channel.get("channelId"))
    if candidate_id:
        channels = [
            dict(candidate_channel) if _text(channel.get("channelId")) == candidate_id else channel
            for channel in channels
        ]
        if all(_text(channel.get("channelId")) != candidate_id for channel in channels):
            channels.append(dict(candidate_channel))

    edge_chain_ids = _edge_chain_ids(overview)
    active: list[dict[str, Any]] = []
    for channel in channels:
        channel_id = _text(channel.get("channelId"))
        if removed_channel_id and channel_id == removed_channel_id:
            continue
        if not _is_provider_ingress_active(channel):
            continue
        if _channel_chain_id(channel, edge_chain_ids) != chain_id:
            continue
        active.append(channel)
    return active


def _edge_chain_ids(overview: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for row in overview.get("sketchInfrastructure", []):
        if not isinstance(row, dict) or _text(row.get("role")) != "edge":
            continue
        chain_id = _text(row.get("chainId"))
        hostname = _text(row.get("hostname"))
        if not chain_id or not hostname:
            continue
        mapping[hostname] = chain_id
        mapping[_short_host(hostname)] = chain_id
    return mapping


def _is_provider_ingress_active(channel: dict[str, Any]) -> bool:
    return _text(channel.get("status")).lower() in ACTIVE_PROVIDER_INGRESS_CHANNEL_STATUSES


def _channel_chain_id(channel: dict[str, Any], edge_chain_ids: dict[str, str]) -> str:
    direct = _text(channel.get("chainId"))
    if direct:
        return direct
    edge = _text(channel.get("edge"))
    return edge_chain_ids.get(edge) or edge_chain_ids.get(_short_host(edge)) or ""


def _terraform_variables(
    provider: str,
    engagement_name: str,
    chain: StoredSketchChain,
    job_input: dict[str, Any],
    plan: ProviderIngressPlan,
    workspace: Path,
    *,
    retained_image: str,
    ownership_tags: tuple[str, ...] = (),
) -> dict[str, Any]:
    effective_engagement_name = _input_text(job_input, "engagementName") or engagement_name
    edge_regions = _input_text_list(job_input, "edgeRegions")
    if not edge_regions:
        edge_regions = [_input_text(job_input, "edgeRegion") or chain.edge_region]
    resource_name_suffix = _input_text(job_input, "resourceNameSuffix") or (
        "" if (workspace / "terraform.tfstate").exists() else _resource_name_suffix(provider, chain.chain_id)
    )
    variables: dict[str, Any] = {
        "engagement_name": _input_text(job_input, "terraformEngagementName")
        or _retained_provider_engagement_name(workspace, provider, resource_name_suffix)
        or _provider_engagement_name(provider, effective_engagement_name),
        "resource_name_suffix": resource_name_suffix,
        "middle_ordinal": _input_int(job_input, "middleOrdinal") or 1,
        "edge_ordinal": _input_int(job_input, "edgeOrdinal") or 1,
        "middle_region": _input_text(job_input, "middleRegion") or chain.middle_region,
        "edge_regions": edge_regions,
        "middle_count": _input_int(job_input, "middleCount") if "middleCount" in job_input else 1,
        "edge_count_per_region": (
            _input_int(job_input, "edgeCountPerRegion")
            if "edgeCountPerRegion" in job_input
            else _input_int(job_input, "edgeCount") if "edgeCount" in job_input else chain.edge_count
        ),
        "allowed_tcp_ports": [str(port) for port in plan.allowed_tcp_ports],
    }
    admin_public = _retained_key_path(
        _input_text(job_input, "infrastructureAdminSshPublicKeyPath")
        or _input_text(job_input, "sshPublicKeyPath"),
        workspace,
        effective_engagement_name,
        provider,
        public=True,
    )
    admin_private = _retained_key_path(
        _input_text(job_input, "infrastructureAdminSshPrivateKeyPath")
        or _input_text(job_input, "sshPrivateKeyPath"),
        workspace,
        effective_engagement_name,
        provider,
        public=False,
    )
    declared_key_values = {
        "infrastructure_admin_ssh_pub_key_path": admin_public,
        "infrastructure_admin_ssh_priv_key_path": admin_private,
        "sketch_transport_ssh_pub_key_path": _input_text(job_input, "sketchTransportSshPublicKeyPath")
        or str(workspace / "keys" / f"{effective_engagement_name}-sketch-transport.pub"),
        "ssh_pub_key_path": admin_public,
        "ssh_priv_key_path": admin_private,
    }
    variables.update(
        {
            name: value
            for name, value in declared_key_values.items()
            if _workspace_declares_variable(workspace, name)
        }
    )
    if _workspace_declares_variable(workspace, "allowed_udp_ports"):
        variables["allowed_udp_ports"] = [str(port) for port in plan.allowed_udp_ports]
    elif plan.allowed_udp_ports:
        raise ValueError("Terraform workspace does not support allowed_udp_ports")
    if _workspace_declares_variable(workspace, "provider_ownership_tags"):
        variables["provider_ownership_tags"] = list(ownership_tags)

    if provider == "linode":
        variables.update(
            {
                "middle_type": _input_text(job_input, "middleSize") or chain.middle_size,
                "edge_type": _input_text(job_input, "edgeSize") or chain.edge_size,
                "linode_image": retained_image,
            }
        )
    elif provider == "digitalocean":
        variables.update(
            {
                "middle_size": _input_text(job_input, "middleSize") or chain.middle_size,
                "edge_size": _input_text(job_input, "edgeSize") or chain.edge_size,
                "docean_image": retained_image,
            }
        )
    else:
        raise ValueError(f"unsupported provider: {provider}")
    return variables


def _resource_name_suffix(provider: str, chain_id: str) -> str:
    if provider == "linode":
        return linode_resource_name_suffix(chain_id)
    if provider == "digitalocean":
        return digitalocean_resource_name_suffix(chain_id)
    raise ValueError(f"unsupported provider: {provider}")


def _provider_engagement_name(provider: str, engagement_name: str) -> str:
    if provider == "linode":
        return linode_provider_name_slug(engagement_name)
    if provider == "digitalocean":
        return digitalocean_provider_name_slug(engagement_name)
    raise ValueError(f"unsupported provider: {provider}")


def _execution_env(
    provider: str,
    alias: str,
    credential_repository: CredentialRepository | None,
    credential_resolver: CredentialResolver,
) -> dict[str, str]:
    if provider == "linode":
        return {LINODE_TOKEN_ENV_VAR: credential_resolver("linode", alias, credential_repository)}
    if provider == "digitalocean":
        return {DIGITALOCEAN_TOKEN_ENV_VAR: credential_resolver("digitalocean", alias, credential_repository)}
    raise ValueError(f"unsupported provider: {provider}")


def _provider_input(provider: str, deploy_job: StoredJobRun, *, provider_role: str) -> dict[str, Any]:
    child_inputs = deploy_job.input.get("childInputs")
    if isinstance(child_inputs, dict):
        for child_input in child_inputs.values():
            if (
                isinstance(child_input, dict)
                and _normalize_provider(child_input.get("provider")) == provider
                and (
                    _input_int(child_input, "middleCount") > 0
                    if provider_role == "middle"
                    else _input_int(child_input, "edgeCount") > 0
                )
            ):
                return child_input
    return deploy_job.input


def _credential_alias(provider: str, job_input: dict[str, Any]) -> str:
    alias = _input_text(job_input, "edgeCredentialAlias") or _input_text(job_input, "middleCredentialAlias")
    if not alias:
        raise ValueError(f"{provider} credential alias is required")
    return alias


def _refresh_provider_firewall_templates(provider: str, workspace: Path) -> list[str]:
    template_dir = {
        "linode": redteam_infra_sketch_template_dir("linode"),
        "digitalocean": redteam_infra_sketch_template_dir("digitalocean"),
    }[provider]
    refreshed: list[str] = []
    # A retained workspace is a deployable revision, not a disposable copy of
    # the current template. Its main.tf and variables.tf must remain from the
    # same revision; the compatibility adapters add narrow firewall inputs.
    for name in ("firewall.tf",):
        source = template_dir / name
        destination = workspace / name
        if not source.exists():
            continue
        if not destination.exists() or source.read_text(encoding="utf-8") != destination.read_text(encoding="utf-8"):
            shutil.copyfile(source, destination)
            refreshed.append(name)
    return refreshed


def _workspace_declares_variable(workspace: Path, variable_name: str) -> bool:
    variables_tf = workspace / "variables.tf"
    if not variables_tf.exists():
        return False
    return f'variable "{variable_name}"' in variables_tf.read_text(encoding="utf-8")


def _retained_provider_engagement_name(workspace: Path, provider: str, resource_name_suffix: str) -> str:
    """Recover an old workspace's opaque Terraform identity from its firewall state.

    The firewall label is used rather than a human-facing node label because
    older Barragan deployments could retain operator aliases for nodes while
    the provider resource itself used an opaque ownership identity.
    """

    state_path = workspace / "terraform.tfstate"
    if not state_path.exists():
        return ""
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    resource_type = "linode_firewall" if provider == "linode" else "digitalocean_firewall"
    attribute = "label" if provider == "linode" else "name"
    for resource in state.get("resources", []):
        if not isinstance(resource, dict) or resource.get("type") != resource_type:
            continue
        for instance in resource.get("instances", []):
            if not isinstance(instance, dict):
                continue
            attributes = instance.get("attributes")
            if not isinstance(attributes, dict):
                continue
            label = str(attributes.get(attribute) or "").strip()
            suffix = f"{resource_name_suffix}-firewall" if resource_name_suffix else "-firewall"
            if label.endswith(suffix):
                return label[: -len(suffix)]
    return ""


def _preserve_retained_firewall_ownership(workspace: Path, provider: str) -> tuple[str, ...]:
    """Keep explicit Barragan ownership tags already recorded in retained state."""

    state_path = workspace / "terraform.tfstate"
    firewall_tf = workspace / "firewall.tf"
    variables_tf = workspace / "variables.tf"
    if not state_path.exists() or not firewall_tf.exists() or not variables_tf.exists():
        return ()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    resource_type = "linode_firewall" if provider == "linode" else "digitalocean_firewall"
    tags: tuple[str, ...] = ()
    for resource in state.get("resources", []):
        if not isinstance(resource, dict) or resource.get("type") != resource_type:
            continue
        for instance in resource.get("instances", []):
            attributes = instance.get("attributes") if isinstance(instance, dict) else None
            values = attributes.get("tags") if isinstance(attributes, dict) else None
            if isinstance(values, list):
                tags = tuple(str(value) for value in values if str(value).strip())
                break
    if not tags:
        return ()

    variables_text = variables_tf.read_text(encoding="utf-8")
    if 'variable "provider_ownership_tags"' not in variables_text:
        variables_tf.write_text(
            variables_text.rstrip()
            + '\nvariable "provider_ownership_tags" {\n  type    = list(string)\n  default = []\n}\n',
            encoding="utf-8",
        )
    firewall_text = firewall_tf.read_text(encoding="utf-8")
    updated_firewall = firewall_text.replace("tags            = [var.engagement_name]", "tags            = var.provider_ownership_tags")
    if updated_firewall != firewall_text:
        firewall_tf.write_text(updated_firewall, encoding="utf-8")
    return tags


def _retained_key_path(
    configured: str,
    workspace: Path,
    engagement_name: str,
    provider: str,
    *,
    public: bool,
) -> str:
    if configured and Path(configured).is_file():
        return configured
    suffix = "-sketch.pub" if public else "-sketch"
    candidates = (
        workspace / "keys" / f"{engagement_name}{suffix}",
        workspace / "keys" / f"{_provider_engagement_name(provider, engagement_name)}{suffix}",
    )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return configured or str(candidates[0])


def _failed(
    provider: str,
    chain_id: str,
    plan: ProviderIngressPlan | None,
    message: str,
    data: dict[str, Any],
) -> ProviderIngressSyncResult:
    return ProviderIngressSyncResult(
        status="failed",
        ok=False,
        provider=provider,
        chain_id=chain_id,
        plan=plan,
        events=(
            ProviderIngressSyncEvent(
                "error",
                message,
                {
                    "provider": provider,
                    "chainId": chain_id,
                    **({"ingressPlan": plan.to_dict()} if plan is not None else {}),
                    **data,
                },
            ),
        ),
    )


def _skipped(
    provider: str,
    chain_id: str,
    plan: ProviderIngressPlan | None,
    message: str,
    data: dict[str, Any],
) -> ProviderIngressSyncResult:
    return ProviderIngressSyncResult(
        status="skipped",
        ok=True,
        provider=provider,
        chain_id=chain_id,
        plan=plan,
        events=(
            ProviderIngressSyncEvent(
                "warning",
                message,
                {
                    "provider": provider,
                    "chainId": chain_id,
                    **({"ingressPlan": plan.to_dict()} if plan is not None else {}),
                    **data,
                },
            ),
        ),
    )


def _safe_terraform_result(
    result: Any, *, sensitive_key_paths: tuple[Path, ...] = ()
) -> dict[str, Any]:
    sensitive_values = {str(path) for path in sensitive_key_paths}
    staging_parent = _specific_key_staging_parent(sensitive_key_paths)
    if staging_parent is not None:
        sensitive_values.add(str(staging_parent))
    for path in sensitive_key_paths:
        try:
            key_content = path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
        if len(key_content) >= 8:
            sensitive_values.add(key_content)
            sensitive_values.add(json.dumps(key_content)[1:-1])

    def sanitized(value: Any) -> str:
        text = str(value or "")
        for sensitive in sorted(sensitive_values, key=len, reverse=True):
            text = text.replace(sensitive, "[REDACTED SKETCH KEY]")
        return _truncate(text)

    return {
        "command": str(getattr(result, "command", "terraform")),
        "returncode": int(getattr(result, "returncode", 1)),
        "stdout": sanitized(getattr(result, "stdout", "")),
        "stderr": sanitized(getattr(result, "stderr", "")),
    }


def _specific_key_staging_parent(paths: tuple[Path, ...]) -> Path | None:
    parents = {path.parent for path in paths}
    if len(parents) != 1:
        return None
    parent = next(iter(parents))
    # ``materialized_sketch_key_files`` owns only these randomized temporary
    # directories. Never redact a generic parent such as /, /tmp, or /keys.
    if not parent.is_absolute() or not parent.name.startswith("barragan-sketch-keys-"):
        return None
    if not parent.name.removeprefix("barragan-sketch-keys-"):
        return None
    return parent


def _truncate(value: str) -> str:
    if len(value) <= MAX_TERRAFORM_OUTPUT_CHARS:
        return value
    return value[:MAX_TERRAFORM_OUTPUT_CHARS] + "\n[truncated]"


def _channel_protocol(channel: dict[str, Any]) -> str:
    protocol = _text(channel.get("protocol")).lower()
    mode = _text(channel.get("mode")).lower()
    if protocol == "udp" or mode == "udp-forward":
        return "udp"
    return "tcp"


def _port(value: Any) -> int:
    try:
        port = int(str(value or "").strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("externalPort must be a TCP or UDP port") from exc
    if port < 1 or port > 65535:
        raise ValueError("externalPort must be between 1 and 65535")
    return port


def _input_text(data: dict[str, Any], key: str) -> str:
    return _text(data.get(key))


def _input_text_list(data: dict[str, Any], key: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _text(item))]


def _input_int(data: dict[str, Any], key: str) -> int:
    try:
        return int(data.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _normalize_provider(value: Any) -> str:
    return _text(value).strip().lower()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _short_host(value: str) -> str:
    return value.split(".", 1)[0] if value else ""
