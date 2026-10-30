# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlparse

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app.core.config import Config
from app.core.request_identity import RequestIdentity, bind_request_identity
from app.core.runtime import initialize_runtime, runtime_context
from app.integrations.oci_compute_profiles import load_oci_compute_profiles, OciComputeProfileError
from app.services.access_plans import PlatformAccessUser
from app.services.backflips_service import (
    BackflipsServiceValidationError,
    apply_backflips_service,
    preview_backflips_service_apply,
)
from app.services.authentication import AuthenticationError, AuthenticationService, PasswordPolicyError
from app.services.authorization import FORCED_CHANGE_PATHS, PUBLIC_PATHS, authorize
from app.services.dashboard import get_dashboard_inventory
from app.services.certificate_manager import (
    CertificateManagerValidationError,
    bind_certificate_to_channel,
    channel_certificate_binding_workspace,
    certificate_manager_workspace,
    create_certificate_asset,
    get_certificate_asset,
    replace_external_certificate,
    retire_certificate_asset,
    start_certificate_issue,
    start_certificate_reissue,
    start_certificate_renew,
    start_certificate_revoke,
    unbind_certificate_from_channel,
    update_certificate_asset_metadata,
    update_certificate_profile,
)
from app.services.catalog import get_template, list_templates, validate_template_input
from app.services.capability_catalog import discover_capability_catalog
from app.services.capability_execution import CapabilityRoleApplyPlanValidationError
from app.services.capability_lock_rendering import render_capability_lock
from app.services.capability_reconciliation import (
    CapabilityReconciliationValidationError,
    assert_capability_reconciliation_idle,
    get_capability_reconciliation,
    recover_interrupted_capability_reconciliations,
    start_capability_reconciliation,
)
from app.services.capability_apply import (
    CapabilityApplyValidationError,
    recover_interrupted_capability_applies,
    start_capability_apply,
)
from app.services.static_web_capability_reconciliation import ensure_static_web_capability_lock
from app.services.capability_profile_resolution import resolve_standard_rti_profile
from app.services.credentials import (
    CredentialDecryptError,
    CredentialStoreLockedError,
    CredentialValidationError,
    create_credential,
    disable_credential,
    list_credentials,
    rotate_credential,
    set_default_credential,
    validate_credential,
)
from app.services.core_deployment_plans import (
    CoreDeploymentPlanError,
    begin_core_deployment_plan_apply,
    get_core_deployment_plan,
    get_current_core_deployment_plan,
    recover_interrupted_core_deployment_plans,
    start_core_deployment_plan,
)
from app.storage.deployment_plan_repository import DeploymentPlanConflictError
from app.services.domains import (
    DomainConfirmationRequired,
    DomainNotFoundError,
    DomainValidationError,
    assign_domain,
    get_cached_hosts,
    get_domain_detail,
    list_domain_groups,
    list_domain_purposes,
    list_engagement_domains,
    patch_domain_assignment,
    patch_domain_catalog_state,
    patch_domain_risk,
    release_domain,
    sync_namecheap_domains,
)
from app.services.engagement_capabilities import (
    EngagementCapabilityValidationError,
    desktop_capability_reconciliation_input,
    engagement_core_provider,
    engagement_capability_workspace,
    update_engagement_capability_selection,
)
from app.services.deployment_orchestrator import plan_standard_rti_deployment
from app.services.digitalocean_provider_validation import (
    DigitalOceanProviderValidationGuardrailError,
    get_guarded_digitalocean_provider_validation_run,
    start_guarded_digitalocean_provider_validation_run,
)
from app.services.engagement_dns import (
    EngagementDnsValidationError,
    get_engagement_dns_workspace,
    preview_engagement_dns,
    recover_interrupted_engagement_dns_applies,
    recover_interrupted_keyed_owned_dns_cleanups,
    start_engagement_dns_apply,
)
from app.services.engagement_operations import EngagementOperationsValidationError, get_operations_overview, update_operations_overview
from app.services.engagements import (
    ActiveInfrastructureError,
    EngagementValidationError,
    archive_engagement,
    configure_engagement_infrastructure,
    create_draft_engagement,
    get_engagement,
    list_engagements,
    retire_engagement,
    update_engagement_metadata,
)
from app.services.engagement_lifecycle import reconcile_engagement_lifecycle
from app.services.engagement_teardown import (
    EngagementTeardownValidationError,
    assert_engagement_mutation_allowed,
    get_engagement_teardown,
    preview_engagement_teardown,
    recover_engagement_teardowns,
    start_engagement_teardown,
    start_engagement_teardown_recovery_monitor,
)
from app.services.engagement_workspaces import (
    DEFAULT_TERRAFORM_STATE_ROOT,
    EngagementWorkspaceValidationError,
    get_engagement_workspace,
    prepare_engagement_workspace,
)
from app.services.generic_service import (
    GenericServiceValidationError,
    create_generic_service,
    disable_generic_service,
    list_generic_services,
    remove_generic_service,
    restore_generic_service,
    update_generic_service,
)
from app.services.guarded_test_deployment import (
    GuardedDeploymentConfirmationError,
    disposable_deployment_readiness,
    get_guarded_pilot_standard_rti_run,
    pilot_standard_rti_readiness,
    run_guarded_disposable_deployment,
    run_guarded_pilot_standard_rti,
    start_guarded_pilot_standard_rti_run,
    start_guarded_pilot_standard_rti_teardown,
)
from app.services.inbound_channel_apply import (
    InboundChannelApplyValidationError,
    preview_inbound_channel_apply,
    remove_inbound_channel,
    start_inbound_channel_apply,
    validate_inbound_channel,
)
from app.services.inbound_channel_batch import (
    InboundChannelBatchConflictError,
    latest_inbound_channel_batch,
    preview_inbound_channel_batch,
    prepare_reviewed_inbound_channel,
    recover_interrupted_inbound_channel_batches,
    retry_inbound_channel_batch,
    start_inbound_channel_batch,
)
from app.services.inbound_channel_certificate import (
    InboundChannelCertificateValidationError,
    auto_configure_http01_channel,
    certificate_workspace,
    issue_certificate,
    renew_certificate,
    revoke_certificate,
)
from app.services.inbound_channel_workflow import (
    InboundChannelWorkflowValidationError,
    create_and_apply_inbound_channel,
    recover_inbound_channel,
)
from app.services.inbound_managed_runtime import (
    InboundManagedRuntimeNotFoundError,
    get_inbound_managed_runtime,
)
from app.services.inbound_request_header_gate import (
    InboundRequestHeaderGateValidationError,
    get_inbound_request_header_gate,
    update_inbound_request_header_gate,
)
from app.services.jobs import JobExecutionError, JobNotFoundError, enqueue_job, get_job_run, list_job_run_page, run_job
from app.services.legacy_homebase_role_service import (
    LegacyHomebaseRoleServiceValidationError,
    apply_desktop_service,
    apply_legacy_homebase_role_service,
    list_desktop_service_catalog,
    list_legacy_homebase_role_catalog,
    preview_desktop_service_apply,
    preview_legacy_homebase_role_service_apply,
)
from app.services.opsec_network_restrictions import (
    OpsecNetworkRestrictionsValidationError,
    apply_opsec_network_restrictions,
    get_opsec_network_restrictions,
)
from app.services.linode_sketch_deployment import (
    LinodeSketchGuardrailError,
    get_guarded_linode_sketch_run,
    start_guarded_linode_sketch_run,
    teardown_guarded_linode_sketch_run,
)
from app.services.outbound_channel_apply import (
    OutboundChannelApplyValidationError,
    apply_outbound_channel,
    preview_outbound_channel_apply,
    remove_outbound_channel,
    validate_outbound_channel,
)
from app.services.observer_checks import (
    InspectionValidationError,
    InspectorCleanupValidationError,
    InspectorReadinessError,
    InspectorSettingsValidationError,
    ObserverCheckValidationError,
    ObserverSettingsValidationError,
    get_inspector_settings,
    get_observer_settings,
    ensure_continuous_inspector_ready,
    list_inspections,
    preview_inspector_cleanup,
    start_inspector_cleanup,
    start_inspection,
    start_observer_check,
    update_inspector_settings,
    update_observer_settings,
)
from app.services.provider_catalog import (
    ProviderCatalogError,
    get_sketch_provider_catalog,
    preflight_digitalocean_sketch_live_readiness,
)
from app.services.provider_orphan_recovery import ProviderOrphanRecoveryError, recover_provider_orphan_candidate
from app.services.post_core_sketch_continuation import (
    recover_post_core_sketch_continuations,
    start_post_core_sketch_recovery_monitor,
)
from app.services.provider_region_policy import (
    ProviderRegionPolicyValidationError,
    list_provider_region_policies,
    update_provider_region_policy,
)
from app.services.revision_compiler import RevisionCompileError
from app.services.revision_rendering import RevisionRenderNotFoundError, render_stored_revision
from app.services.revisions import RevisionNotFoundError, create_revision, get_revision, list_revisions
from app.services.sketch_chains import (
    SketchChainValidationError,
    cancel_sketch_chain,
    create_sketch_chain,
    deploy_sketch_chain,
    ensure_sketch_chain_teardown,
    list_sketch_chains,
    refresh_sketch_chain_from_job,
    replace_sketch_chain_final_edge,
    retire_sketch_chain_final_edge,
    start_sketch_chain,
    stop_sketch_chain,
    update_sketch_chain,
)
from app.services.sketch_ssh_keys import (
    SketchSshKeyNotFoundError,
    SketchSshKeyRemovalError,
    SketchSshKeyRotationError,
    ensure_sketch_ssh_key,
    get_sketch_ssh_key_metadata,
    preview_sketch_ssh_key_removal,
    preview_sketch_ssh_key_rotation,
    remove_sketch_ssh_key,
    retrieve_sketch_ssh_key,
    rotate_sketch_ssh_key,
)
from app.services.sketch_lifecycle_recovery import (
    recover_sketch_lifecycle,
    start_sketch_lifecycle_recovery_monitor,
)
from app.services.team_access import (
    TeamAccessValidationError,
    add_team_member_ssh_key,
    apply_team_import,
    create_team_member,
    deactivate_team_member,
    enroll_engagement_member,
    get_engagement_team,
    list_team_members,
    preview_team_import,
    preview_engagement_access_plan,
    remove_engagement_membership,
    retire_team_member_ssh_key,
    start_engagement_access_apply,
    update_engagement_membership,
    update_team_member,
    update_team_member_ssh_key,
)
from app.services.template_compatibility import audit_redteam_infra_template
from app.services.web_static_service import (
    WebStaticServiceValidationError,
    list_web_static_services,
    preview_web_static_service_apply,
    preview_web_static_service_remove,
    start_web_static_service_apply,
    start_web_static_service_remove,
)
from app.storage.models import JobRunModel


class BarraganFastAPI(FastAPI):
    config: dict[str, Any]

    def storage_context(self):
        return runtime_context(self.state.runtime)

    def test_client(self):
        from app.testing import CompatibilityTestClient

        return CompatibilityTestClient(self)


def create_app(config_object: type[Config] | None = None) -> BarraganFastAPI:
    config = config_object or Config
    compute_profiles_file = str(getattr(config, "OCI_COMPUTE_PROFILES_FILE", "") or "").strip()
    if getattr(config, "ENVIRONMENT", "local") == "production" and not compute_profiles_file:
        raise OciComputeProfileError("BARRAGAN_OCI_COMPUTE_PROFILES_FILE is required in production")
    if compute_profiles_file:
        load_oci_compute_profiles(compute_profiles_file)
    runtime_state = initialize_runtime(config, make_default=True)
    database_state = runtime_state.database
    app = BarraganFastAPI(title="Barragan API", version="0.1.0")
    app.state.database = database_state
    app.state.config = config
    app.state.runtime = runtime_state
    app.state.authentication = AuthenticationService.from_config(config)
    app.config = {
        key: getattr(config, key)
        for key in dir(config)
        if key.isupper()
    }

    if getattr(config, "START_SCHEDULERS", True):
        from app.services.certificate_scheduler import start_certificate_scheduler
        from app.services.inspector_scheduler import start_inspector_scheduler

        start_inspector_scheduler(runtime_state)
        start_certificate_scheduler(runtime_state)

    # Recovery is scheduled while the runtime is initialized and before the
    # application is returned to the server, so no mounted browser is needed.
    with runtime_context(runtime_state):
        from app.core.runtime import start_runtime_task

        recover_interrupted_engagement_dns_applies(
            schedule=lambda task: start_runtime_task(
                task, name="barragan-dns-apply-recovery",
            ),
        )
        if getattr(config, "ENVIRONMENT", "") == "devtest":
            from app.services.sketch_state_workspaces import _default_state_root

            recover_interrupted_keyed_owned_dns_cleanups(
                environment="devtest", state_root=_default_state_root(),
                schedule=lambda task: start_runtime_task(
                    task, name="barragan-keyed-owned-dns-recovery",
                ),
            )
        # Process-local workers cannot survive restart. Clear/fail their core
        # leases before durable teardown recovery attempts to reacquire one.
        recover_interrupted_core_deployment_plans()
        if (getattr(config, "ENVIRONMENT", "") == "devtest"
                and getattr(config, "PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED", False) is True):
            from app.core.runtime import start_runtime_task
            from app.services.provider_keyed_initial_dispatch import recover_fresh_keyed_initial_dispatches

            recover_fresh_keyed_initial_dispatches(
                environment="devtest", rollout_enabled=True,
                schedule=lambda task: start_runtime_task(
                    task, name="barragan-keyed-initial-recovery",
                ),
            )
            from app.services.provider_keyed_mixed_initial_public import (
                recover_reviewed_mixed_initial_dispatches,
            )

            recover_reviewed_mixed_initial_dispatches(
                environment="devtest", rollout_enabled=True,
                schedule=lambda task: start_runtime_task(
                    task, name="barragan-mixed-initial-recovery",
                ),
            )
        if (getattr(config, "ENVIRONMENT", "") == "devtest"
                and getattr(config, "PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED", False) is True):
            from app.services.provider_keyed_append_dispatch import (
                recover_approved_digitalocean_edge_appends,
            )
            recover_approved_digitalocean_edge_appends(
                environment="devtest", rollout_enabled=True,
                schedule=lambda task: start_runtime_task(
                    task, name="barragan-keyed-edge-append-recovery",
                ),
            )
        if getattr(config, "ENVIRONMENT", "") == "devtest":
            from app.services.provider_keyed_mixed_append_review_runtime import (
                recover_mixed_append_reviews,
            )

            recover_mixed_append_reviews(
                environment="devtest",
                schedule=lambda task: start_runtime_task(
                    task, name="barragan-mixed-append-review-recovery",
                ),
            )
            from app.services.provider_keyed_mixed_append_apply_runtime import (
                recover_approved_mixed_append_applies,
            )

            recover_approved_mixed_append_applies(
                environment="devtest",
                schedule=lambda task: start_runtime_task(
                    task, name="barragan-mixed-append-apply-recovery",
                ),
            )
        recover_interrupted_capability_reconciliations()
        recover_interrupted_capability_applies()
        recover_interrupted_inbound_channel_batches()
        recover_post_core_sketch_continuations()
        recover_engagement_teardowns()
        if getattr(config, "ENVIRONMENT", "") == "devtest":
            from app.services.provider_keyed_pending_dispatch import (
                advance_pending_keyed_terminal, recover_pending_keyed_dispatches,
                require_positive_control_ipv4,
            )
            from app.services.sketch_state_workspaces import _default_state_root

            control = getattr(config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", "")
            try:
                require_positive_control_ipv4(control)
            except ValueError:
                pass  # No server-selected public control: no pending cleanup is scheduled.
            else:
                state_root = _default_state_root()

                def schedule_pending(parent_id: str, delay: float) -> None:
                    def resume() -> None:
                        if delay:
                            from threading import Event
                            Event().wait(delay)
                        eligible = {}
                        recover_pending_keyed_dispatches(
                            environment="devtest", state_root=state_root,
                            positive_control_ipv4=control,
                            schedule=lambda candidate, remaining: eligible.update({candidate: remaining}),
                        )
                        if eligible.get(parent_id) != 0.0:
                            return
                        advance_pending_keyed_terminal(
                            parent_id, environment="devtest", state_root=state_root,
                            positive_control_ipv4=control,
                        )

                    start_runtime_task(resume, name="barragan-keyed-pending-teardown-recovery")

                recover_pending_keyed_dispatches(
                    environment="devtest", state_root=state_root,
                    positive_control_ipv4=control,
                    schedule=schedule_pending,
                )
                from app.services.provider_keyed_published_dispatch import (
                    advance_published_keyed_terminal, recover_published_keyed_dispatches,
                )

                def schedule_published(parent_id: str, delay: float) -> None:
                    def resume() -> None:
                        if delay:
                            from threading import Event
                            Event().wait(delay)
                        eligible = {}
                        recover_published_keyed_dispatches(
                            environment="devtest", state_root=state_root,
                            positive_control_ipv4=control,
                            schedule=lambda candidate, remaining: eligible.update(
                                {candidate: remaining}),
                        )
                        if eligible.get(parent_id) != 0.0:
                            return
                        advance_published_keyed_terminal(
                            parent_id, environment="devtest", state_root=state_root,
                            positive_control_ipv4=control,
                        )

                    start_runtime_task(resume, name="barragan-keyed-published-teardown-recovery")

                recover_published_keyed_dispatches(
                    environment="devtest", state_root=state_root,
                    positive_control_ipv4=control,
                    schedule=schedule_published,
                )
                from app.services.provider_keyed_mixed_zero_apply_dispatch import (
                    advance_mixed_zero_apply_cleanup, recover_mixed_zero_apply_dispatches,
                )

                def schedule_mixed_zero_apply(parent_id: str) -> None:
                    def resume() -> None:
                        eligible = []
                        recover_mixed_zero_apply_dispatches(
                            environment="devtest", schedule=eligible.append)
                        if parent_id in eligible:
                            advance_mixed_zero_apply_cleanup(
                                parent_id, environment="devtest",
                                positive_control_ipv4=control,
                            )

                    start_runtime_task(resume, name="barragan-mixed-zero-apply-teardown-recovery")

                recover_mixed_zero_apply_dispatches(
                    environment="devtest", schedule=schedule_mixed_zero_apply,
                )
                from app.services.provider_keyed_mixed_interrupted_public import (
                    advance_mixed_interrupted_cleanup,
                    recover_mixed_interrupted_dispatches,
                )

                def schedule_mixed_interrupted(parent_id: str) -> None:
                    def resume() -> None:
                        eligible = []
                        recover_mixed_interrupted_dispatches(
                            environment="devtest", schedule=eligible.append,
                        )
                        if parent_id in eligible:
                            advance_mixed_interrupted_cleanup(
                                parent_id, environment="devtest",
                                positive_control_ipv4=control,
                            )

                    start_runtime_task(
                        resume, name="barragan-mixed-interrupted-teardown-recovery")

                recover_mixed_interrupted_dispatches(
                    environment="devtest", schedule=schedule_mixed_interrupted,
                )
                from app.services.provider_keyed_mixed_published_public import (
                    advance_published_mixed_cleanup,
                    recover_published_mixed_dispatches,
                )
                from app.services.provider_keyed_mixed_published_dispatch_claim import (
                    schedule_published_mixed_dispatch,
                )

                def schedule_mixed_published(parent_id: str) -> None:
                    schedule_published_mixed_dispatch(
                        parent_id, environment="devtest",
                        positive_control_ipv4=control,
                        name="barragan-mixed-published-teardown-recovery",
                        coordinator=advance_published_mixed_cleanup,
                        start_task=start_runtime_task)

                recover_published_mixed_dispatches(
                    environment="devtest", schedule=schedule_mixed_published,
                )
        recover_sketch_lifecycle(startup=True)
        # Dev/test deliberately disables schedulers so a disposable live proof
        # has no periodic worker competing with its explicit startup recovery.
        # Startup recovery remains mandatory; only the recurring monitors obey
        # the scheduler switch.
        if not bool(getattr(config, "TESTING", False)) and bool(getattr(config, "START_SCHEDULERS", True)):
            start_post_core_sketch_recovery_monitor()
            start_engagement_teardown_recovery_monitor()
            start_sketch_lifecycle_recovery_monitor()

    from app.storage.job_repository import MixedAppendBindingFenceError

    @app.exception_handler(MixedAppendBindingFenceError)
    def append_binding_fence_handler(_request: Request, _exc: MixedAppendBindingFenceError) -> JSONResponse:
        return JSONResponse({"errors": [
            "channel and service changes are unavailable during paired edge append"
        ]}, status_code=409)

    @app.exception_handler(HTTPException)
    def http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "request failed"
        return JSONResponse({"error": detail}, status_code=exc.status_code)

    @app.middleware("http")
    async def authenticate_request(request: Request, call_next):
        path = request.url.path
        auth_required = bool(getattr(config, "AUTH_REQUIRED", False))
        protected_surface = path.startswith("/api/") or path in {"/docs", "/redoc", "/openapi.json"}
        if (
            not protected_surface
            or path in PUBLIC_PATHS
            or (not auth_required and not path.startswith("/api/auth/"))
        ):
            return await call_next(request)
        token = request.cookies.get(str(getattr(config, "AUTH_SESSION_COOKIE_NAME")), "")
        try:
            with _storage_context(app):
                if request.method.upper() in {"GET", "HEAD", "OPTIONS"}:
                    identity = app.state.authentication.resolve_session(token)
                else:
                    identity = app.state.authentication.validate_csrf(
                        token,
                        request.headers.get("X-Barragan-CSRF", ""),
                    )
        except AuthenticationError as exc:
            response = JSONResponse({"error": str(exc)}, status_code=401)
            _clear_session_cookie(response, config)
            return response
        if identity.must_change_password and path not in FORCED_CHANGE_PATHS:
            return JSONResponse({"error": "password change required"}, status_code=403)
        if path not in FORCED_CHANGE_PATHS:
            decision = authorize(identity.roles, request.method, path)
            if not decision.allowed:
                return JSONResponse({"error": f"not authorized for {decision.action.value}"}, status_code=403)
        request.state.identity = identity
        request_identity = RequestIdentity(
            user_id=identity.team_member_id,
            username=identity.username,
            roles=identity.roles,
            session_id=identity.session_id,
        )
        with bind_request_identity(request_identity):
            return await call_next(request)

    @app.middleware("http")
    async def block_conflicting_engagement_mutations(request: Request, call_next):
        engagement_id = _operational_mutation_engagement_id(request.method, request.url.path)
        if engagement_id:
            try:
                with _storage_context(app):
                    assert_engagement_mutation_allowed(engagement_id)
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
        capability_engagement_id = _core_host_mutation_engagement_id(request.method, request.url.path)
        if capability_engagement_id:
            try:
                with _storage_context(app):
                    assert_capability_reconciliation_idle(capability_engagement_id)
            except CapabilityReconciliationValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
        return await call_next(request)

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        with _storage_context(app):
            return {"service": "barragan-api", "status": "ok", "database": _database_status(app)}

    @app.post("/api/auth/login")
    async def auth_login(request: Request) -> JSONResponse:
        body = await _json_body(request)
        try:
            with _storage_context(app):
                issued = app.state.authentication.authenticate(
                    str(body.get("username") or ""),
                    str(body.get("password") or ""),
                )
        except AuthenticationError as exc:
            status_code = 423 if exc.code == "account_locked" else 401
            return JSONResponse({"error": str(exc)}, status_code=status_code)
        response = JSONResponse(_auth_session_payload(issued.identity, issued.csrf_token))
        _set_session_cookie(response, config, issued.session_token)
        return response

    @app.get("/api/auth/session")
    def auth_session(request: Request) -> JSONResponse:
        token = request.cookies.get(str(getattr(config, "AUTH_SESSION_COOKIE_NAME")), "")
        if not token:
            return JSONResponse(_anonymous_session_payload(config))
        try:
            with _storage_context(app):
                identity = app.state.authentication.resolve_session(token)
        except AuthenticationError:
            response = JSONResponse(_anonymous_session_payload(config))
            _clear_session_cookie(response, config)
            return response
        return JSONResponse(_auth_session_payload(identity))

    @app.post("/api/auth/password")
    async def auth_password(request: Request) -> JSONResponse:
        identity = getattr(request.state, "identity", None)
        token = request.cookies.get(str(getattr(config, "AUTH_SESSION_COOKIE_NAME")), "")
        body = await _json_body(request)
        if identity is None or not token:
            raise HTTPException(status_code=401, detail="authentication required")
        current_password = str(body.get("currentPassword") or "")
        new_password = str(body.get("newPassword") or "")
        try:
            with _storage_context(app):
                app.state.authentication.change_password(token, current_password, new_password)
                issued = app.state.authentication.authenticate(identity.username, new_password)
        except PasswordPolicyError as exc:
            return JSONResponse({"errors": list(exc.errors), "error": str(exc)}, status_code=400)
        except AuthenticationError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        response = JSONResponse(_auth_session_payload(issued.identity, issued.csrf_token))
        _set_session_cookie(response, config, issued.session_token)
        return response

    @app.post("/api/auth/logout")
    def auth_logout(request: Request) -> JSONResponse:
        token = request.cookies.get(str(getattr(config, "AUTH_SESSION_COOKIE_NAME")), "")
        with _storage_context(app):
            app.state.authentication.logout(token)
        response = JSONResponse({"authenticated": False})
        _clear_session_cookie(response, config)
        return response

    @app.post("/api/auth/logout-all")
    def auth_logout_all(request: Request) -> JSONResponse:
        identity = getattr(request.state, "identity", None)
        if identity is None:
            raise HTTPException(status_code=401, detail="authentication required")
        with _storage_context(app):
            app.state.authentication.revoke_sessions(
                identity.credential_id,
                actor=f"user:{identity.credential_id}",
                reason="logout_all",
            )
        response = JSONResponse({"authenticated": False})
        _clear_session_cookie(response, config)
        return response

    @app.get("/api/templates")
    def templates_index() -> dict[str, Any]:
        with _storage_context(app):
            return {"templates": [template.to_dict() for template in list_templates()]}

    @app.get("/api/templates/redteam-infra/compatibility")
    def redteam_infra_template_compatibility() -> dict[str, Any]:
        return {"compatibility": audit_redteam_infra_template().to_dict()}

    @app.get("/api/templates/redteam-infra/capabilities")
    def redteam_infra_template_capabilities() -> dict[str, Any]:
        return {"catalog": discover_capability_catalog().to_dict()}

    @app.get("/api/templates/redteam-infra/profiles/standard-rti")
    def redteam_infra_standard_rti_profile() -> dict[str, Any]:
        return {"profileResolution": resolve_standard_rti_profile().to_dict()}

    @app.get("/api/templates/{template_id}")
    def templates_show(template_id: str) -> dict[str, Any]:
        with _storage_context(app):
            template = get_template(template_id)
            if template is None:
                raise HTTPException(status_code=404, detail="template not found")
            return {"template": template.to_dict()}

    @app.post("/api/templates/{template_id}/validate")
    async def templates_validate(template_id: str, request: Request) -> JSONResponse:
        body = await _json_body(request)
        with _storage_context(app):
            result = validate_template_input(template_id, body)
            return JSONResponse({"validation": result.to_dict()}, status_code=200 if result.valid else 400)

    @app.get("/api/jobs")
    def jobs_index(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        with _storage_context(app):
            return list_job_run_page(limit=limit, offset=offset).to_dict()

    @app.post("/api/jobs")
    async def jobs_create(request: Request) -> JSONResponse:
        body = await _json_body(request)
        with _storage_context(app):
            job = enqueue_job(
                action=str(body.get("action", "")).strip(),
                target_type=str(body.get("targetType", "system")).strip(),
                target_id=str(body.get("targetId", "manual")).strip(),
                requested_by=str(body.get("requestedBy", "system")).strip(),
                input_data=dict(body.get("input", {})),
            )
            return JSONResponse({"job": job.to_dict()}, status_code=201)

    @app.get("/api/jobs/{job_id}")
    def jobs_show(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            job = get_job_run(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="job not found")
            return {"job": job.to_dict()}

    @app.post("/api/jobs/{job_id}/run")
    def jobs_run(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            try:
                job = run_job(job_id)
            except JobNotFoundError:
                raise HTTPException(status_code=404, detail="job not found") from None
            except JobExecutionError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            return {"job": job.to_dict()}

    @app.get("/api/provider-catalog/sketch")
    def sketch_provider_catalog(
        provider: str = "",
        refresh: str = "",
        includeBlocked: str = "",
    ) -> dict[str, Any]:
        with _storage_context(app):
            try:
                catalog = get_sketch_provider_catalog(
                    provider.strip(),
                    refresh=_truthy(refresh),
                    include_blocked=_truthy(includeBlocked),
                )
            except ProviderCatalogError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            return {"catalog": catalog.to_dict()}

    @app.get("/api/provider-catalog/sketch/region-policies")
    def sketch_region_policies_index() -> dict[str, Any]:
        with _storage_context(app):
            return {"policies": [policy.to_dict() for policy in list_provider_region_policies()]}

    @app.patch("/api/provider-catalog/sketch/region-policies/{provider}")
    async def sketch_region_policy_update(provider: str, request: Request) -> dict[str, Any]:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                policy = update_provider_region_policy(provider, body)
            except ProviderRegionPolicyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return {"policy": policy.to_dict()}

    @app.post("/api/provider-catalog/sketch/digitalocean/preflight")
    def digitalocean_sketch_preflight() -> JSONResponse:
        with _storage_context(app):
            preflight = preflight_digitalocean_sketch_live_readiness()
            return JSONResponse({"preflight": preflight.to_dict()}, status_code=200 if preflight.ready else 400)

    @app.post("/api/orchestrator/standard-rti/plan")
    async def orchestrator_standard_rti_plan(request: Request) -> dict[str, Any]:
        body = await _json_body(request)
        access_users = [
            PlatformAccessUser(
                user_id=user.get("userId", ""),
                username=user.get("username", ""),
                credential_ref=user.get("credentialRef", ""),
                privileges=list(user.get("privileges", [])),
            )
            for user in body.get("accessUsers", [])
            if isinstance(user, dict)
        ]
        render_destination = body.get("renderDestination")
        with _storage_context(app):
            result = plan_standard_rti_deployment(
                engagement_id=body.get("engagementId", "eng-plan-preview"),
                input_parameters=body.get("inputParameters", {}),
                access_users=access_users,
                render_destination=Path(render_destination) if render_destination else None,
            )
            return {"plan": result.to_dict()}

    @app.get("/api/orchestrator/barragan-testing/disposable/readiness")
    def orchestrator_disposable_readiness() -> dict[str, Any]:
        with _storage_context(app):
            return {"readiness": disposable_deployment_readiness()}

    @app.post("/api/orchestrator/barragan-testing/disposable/run")
    async def orchestrator_disposable_run(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = run_guarded_disposable_deployment(body)
            except GuardedDeploymentConfirmationError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            return result

    @app.get("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")
    def orchestrator_pilot_standard_rti_readiness(engagementId: str | None = None) -> dict[str, Any]:
        with _storage_context(app):
            return {"readiness": pilot_standard_rti_readiness(engagement_id=engagementId)}

    @app.post("/api/engagements/{engagement_id}/deployment-plans")
    async def engagement_deployment_plans_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                plan = start_core_deployment_plan(
                    engagement_id,
                    body,
                    engagement_workspace_root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                    terraform_state_root=Path(getattr(app.state.config, "TERRAFORM_STATE_ROOT", DEFAULT_TERRAFORM_STATE_ROOT)),
                )
            except CoreDeploymentPlanError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except DeploymentPlanConflictError as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            return JSONResponse({"plan": _core_plan_public_detail(app.state.config, plan)}, status_code=202)

    @app.get("/api/engagements/{engagement_id}/deployment-plans/current")
    def engagement_deployment_plans_current(engagement_id: str) -> Any:
        with _storage_context(app):
            plan = get_current_core_deployment_plan(engagement_id)
            return {"plan": _core_plan_public_detail(app.state.config, plan) if plan is not None else None}

    @app.get("/api/engagements/{engagement_id}/deployment-plans/{plan_id}")
    def engagement_deployment_plans_show(engagement_id: str, plan_id: str) -> Any:
        with _storage_context(app):
            plan = get_core_deployment_plan(engagement_id, plan_id)
            if plan is None:
                raise HTTPException(status_code=404, detail="deployment plan not found")
            return {"plan": _core_plan_public_detail(app.state.config, plan)}

    @app.post("/api/engagements/{engagement_id}/deployment-plans/{plan_id}/apply")
    async def engagement_deployment_plans_apply(engagement_id: str, plan_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                reviewed = get_core_deployment_plan(engagement_id, plan_id)
                if (reviewed is not None
                        and reviewed.evidence.get("sketchStateSchema") == "provider-keyed-v2"):
                    from app.services.core_deployment_plans import _begin_private_devtest_keyed_core_plan_apply
                    from app.services.guarded_test_deployment import EXECUTION_CONFIRMATION

                    if not _keyed_core_plan_deploy_eligible(app.state.config, reviewed):
                        raise CoreDeploymentPlanError(["reviewed keyed DevTest deployment is unavailable"])
                    if body.get("confirmMutation") != EXECUTION_CONFIRMATION:
                        raise CoreDeploymentPlanError([
                            f'confirmMutation must equal "{EXECUTION_CONFIRMATION}"',
                        ])
                    plan, job = _begin_private_devtest_keyed_core_plan_apply(engagement_id, plan_id)
                else:
                    plan, job = begin_core_deployment_plan_apply(
                        engagement_id,
                        plan_id,
                        body,
                        engagement_workspace_root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                        terraform_state_root=Path(getattr(app.state.config, "TERRAFORM_STATE_ROOT", DEFAULT_TERRAFORM_STATE_ROOT)),
                    )
            except CoreDeploymentPlanError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except DeploymentPlanConflictError as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            except (GuardedDeploymentConfirmationError, EngagementWorkspaceValidationError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            return JSONResponse({"plan": _core_plan_public_detail(app.state.config, plan),
                                 "job": job.to_dict()}, status_code=201)

    @app.post("/api/orchestrator/barragan-testing/pilot-standard-rti/run")
    async def orchestrator_pilot_standard_rti_run(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = run_guarded_pilot_standard_rti(
                    body,
                    engagement_workspace_root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                    allow_legacy_internal=False,
                )
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except (GuardedDeploymentConfirmationError, EngagementWorkspaceValidationError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            return result

    @app.post("/api/orchestrator/barragan-testing/pilot-standard-rti/runs")
    async def orchestrator_pilot_standard_rti_runs_create(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                engagement_id = str(body.get("engagementId") or "").strip()
                if engagement_id:
                    assert_engagement_mutation_allowed(engagement_id)
                job = start_guarded_pilot_standard_rti_run(
                    body,
                    engagement_workspace_root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except (GuardedDeploymentConfirmationError, EngagementWorkspaceValidationError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            return JSONResponse({"job": job.to_dict()}, status_code=201)

    @app.get("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{job_id}")
    def orchestrator_pilot_standard_rti_runs_show(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            job = get_guarded_pilot_standard_rti_run(job_id)
            mixed_parent = None
            if job is None:
                parent = get_engagement_teardown(job_id)
                if parent is None:
                    from app.services.provider_keyed_mixed_zero_apply_cleanup import ACTION as MIXED_CLEANUP_ACTION
                    from app.services.provider_keyed_mixed_interrupted_cleanup import ACTION as INTERRUPTED_CLEANUP_ACTION
                    from app.services.provider_keyed_mixed_published_teardown_checkpoint import ACTION as PUBLISHED_MIXED_CLEANUP_ACTION
                    from app.storage.job_repository import SqlAlchemyJobRepository
                    candidate = SqlAlchemyJobRepository().get(job_id)
                    parent = (candidate if candidate is not None and candidate.action in {
                        MIXED_CLEANUP_ACTION, INTERRUPTED_CLEANUP_ACTION,
                        PUBLISHED_MIXED_CLEANUP_ACTION} else None)
                    mixed_parent = parent
                job = parent.to_detail() if parent is not None else None
            if job is None:
                raise HTTPException(status_code=404, detail="pilot run not found")
            detail = job.to_dict()
            if mixed_parent is not None:
                from app.services.engagement_operations import _teardown_job_summary
                from app.storage.job_repository import SqlAlchemyJobRepository
                jobs = SqlAlchemyJobRepository()
                progress = _teardown_job_summary(
                    mixed_parent, jobs.list_for_engagement(mixed_parent.target_id), job_repository=jobs)
                detail["phase"] = progress["phase"]
                detail["progress"] = progress["progress"]
                for key in ("dispatch", "activeChild", "activeChildState"):
                    if key in progress:
                        detail[key] = progress[key]
            return {"job": detail}

    @app.get("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{job_id}/teardown")
    def orchestrator_pilot_standard_rti_runs_teardown_preview(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            try:
                from app.services.provider_keyed_mixed_zero_apply_dispatch import (
                    MixedZeroApplyDispatchAttention, is_mixed_zero_apply_request,
                    preview_mixed_zero_apply_cleanup,
                )
                from app.services.provider_keyed_mixed_interrupted_dispatch import (
                    MixedInterruptedDispatchAttention, is_mixed_interrupted_request,
                    preview_mixed_interrupted_cleanup,
                )
                from app.services.provider_keyed_mixed_published_dispatch import (
                    PublishedMixedDispatchAttention, is_published_mixed_request,
                    preview_published_mixed_cleanup,
                )
                from app.storage.job_repository import SqlAlchemyJobRepository
                requested = SqlAlchemyJobRepository().get(job_id)
                if is_published_mixed_request(requested, SqlAlchemyJobRepository()):
                    teardown = preview_published_mixed_cleanup(
                        requested, environment=getattr(app.state.config, "ENVIRONMENT", ""))
                    return {"teardown": teardown}
                if is_mixed_zero_apply_request(requested):
                    teardown = preview_mixed_zero_apply_cleanup(
                        requested, environment=getattr(app.state.config, "ENVIRONMENT", ""))
                    return {"teardown": teardown}
                if is_mixed_interrupted_request(requested):
                    teardown = preview_mixed_interrupted_cleanup(
                        requested, environment=getattr(app.state.config, "ENVIRONMENT", ""))
                    return {"teardown": teardown}
                teardown = preview_engagement_teardown(job_id)
            except (EngagementTeardownValidationError, MixedZeroApplyDispatchAttention,
                    MixedInterruptedDispatchAttention,
                    PublishedMixedDispatchAttention) as exc:
                return JSONResponse({"errors": getattr(exc, "errors", [str(exc)])}, status_code=400)
            if teardown is None:
                raise HTTPException(status_code=404, detail="pilot run not found")
            return {"teardown": teardown}

    @app.post("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{job_id}/teardown")
    async def orchestrator_pilot_standard_rti_runs_teardown(job_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                from app.services.provider_keyed_mixed_zero_apply_dispatch import (
                    MixedZeroApplyDispatchAttention, advance_mixed_zero_apply_cleanup,
                    is_mixed_zero_apply_request, start_mixed_zero_apply_cleanup,
                )
                from app.services.provider_keyed_mixed_interrupted_dispatch import (
                    MixedInterruptedDispatchAttention, is_mixed_interrupted_request,
                    start_mixed_interrupted_cleanup,
                )
                from app.services.provider_keyed_mixed_published_dispatch import (
                    PublishedMixedDispatchAttention, is_published_mixed_request,
                    start_published_mixed_cleanup,
                )
                from app.storage.job_repository import SqlAlchemyJobRepository
                requested_mixed = SqlAlchemyJobRepository().get(job_id)
                if is_published_mixed_request(requested_mixed, SqlAlchemyJobRepository()):
                    from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
                    control = require_positive_control_ipv4(
                        getattr(app.state.config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
                    job = start_published_mixed_cleanup(
                        requested_mixed, body,
                        environment=getattr(app.state.config, "ENVIRONMENT", ""))
                    if job.status == "queued":
                        from app.core.runtime import start_runtime_task
                        from app.services.provider_keyed_mixed_published_public import (
                            advance_published_mixed_cleanup,
                        )
                        from app.services.provider_keyed_mixed_published_dispatch_claim import (
                            schedule_published_mixed_dispatch,
                        )
                        schedule_published_mixed_dispatch(
                            job.id, environment="devtest",
                            positive_control_ipv4=control,
                            name="barragan-mixed-published-teardown",
                            coordinator=advance_published_mixed_cleanup,
                            start_task=start_runtime_task)
                    return {"job": job.to_detail().to_dict()}
                if is_mixed_zero_apply_request(requested_mixed):
                    from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
                    control = require_positive_control_ipv4(
                        getattr(app.state.config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
                    job = start_mixed_zero_apply_cleanup(
                        requested_mixed, body,
                        environment=getattr(app.state.config, "ENVIRONMENT", ""),
                    )
                    if job.status == "queued":
                        from app.core.runtime import start_runtime_task
                        start_runtime_task(
                            lambda: advance_mixed_zero_apply_cleanup(
                                job.id, environment="devtest",
                                positive_control_ipv4=control,
                            ), name="barragan-mixed-zero-apply-teardown",
                        )
                    return {"job": job.to_detail().to_dict()}
                if is_mixed_interrupted_request(requested_mixed):
                    from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4
                    from app.services.provider_keyed_mixed_interrupted_cleanup import (
                        _parent_id as interrupted_cleanup_id,
                    )
                    control = require_positive_control_ipv4(
                        getattr(app.state.config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
                    core_id = (requested_mixed.input.get("coreJobId")
                               if requested_mixed.action == "provider_keyed_mixed_interrupted_cleanup"
                               else requested_mixed.id)
                    already_reserved = SqlAlchemyJobRepository().get(
                        interrupted_cleanup_id(core_id)) is not None
                    job = start_mixed_interrupted_cleanup(
                        requested_mixed, body,
                        environment=getattr(app.state.config, "ENVIRONMENT", ""),
                    )
                    if job.status == "queued" and not already_reserved:
                        from app.core.runtime import start_runtime_task
                        from app.services.provider_keyed_mixed_interrupted_public import (
                            advance_mixed_interrupted_cleanup,
                        )
                        start_runtime_task(
                            lambda: advance_mixed_interrupted_cleanup(
                                job.id, environment="devtest",
                                positive_control_ipv4=control,
                            ), name="barragan-mixed-interrupted-teardown",
                        )
                    return {"job": job.to_detail().to_dict()}
                from app.services.engagement_teardown import (
                    ENGAGEMENT_TEARDOWN_ACTION, _current_scope_snapshot,
                    _is_provider_keyed_v2, _parent_id,
                )
                from app.services.provider_keyed_pending_dispatch import (
                    PendingKeyedDispatchAttention, advance_pending_keyed_terminal,
                    require_positive_control_ipv4, require_prequeue_pending_diagnostic,
                )
                from app.services.provider_keyed_published_dispatch import (
                    PublishedKeyedDispatchAttention, advance_published_keyed_terminal,
                    require_prequeue_published_generation,
                )
                from app.services.provider_keyed_comprehensive_teardown import (
                    _boundary, _child_id, run_provider_keyed_comprehensive_handoff,
                )
                from app.services.provider_keyed_pending_dispatch import _require_diagnostic_scope
                from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
                from app.services.provider_keyed_teardown_source import load_keyed_teardown_source
                from app.services.provider_keyed_initial_continuation import _job_ids
                from app.services.sketch_state_workspaces import _default_state_root
                from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
                from app.storage.job_repository import SqlAlchemyJobRepository
                from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
                from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

                jobs = SqlAlchemyJobRepository()
                requested = jobs.get(job_id)
                core = (jobs.get(str(requested.input.get("coreJobId") or ""))
                        if requested is not None and requested.action == ENGAGEMENT_TEARDOWN_ACTION
                        else requested)
                keyed = core is not None and _is_provider_keyed_v2(core)
                if keyed:
                    if getattr(app.state.config, "ENVIRONMENT", "") != "devtest":
                        raise PendingKeyedDispatchAttention("keyed teardown execution is unavailable")
                    existing = jobs.get(_parent_id(core.id))
                    if existing is not None and existing.status == "succeeded":
                        job = start_engagement_teardown(
                            job_id, body, provider_keyed_environment="devtest",
                            provider_keyed_coordinator=lambda _parent_id: existing,
                        )
                        return {"job": job.to_detail().to_dict()}
                    control = require_positive_control_ipv4(
                        getattr(app.state.config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
                    state_root = _default_state_root()
                    initial = jobs.get(_job_ids(core.id)[0])
                    published = (existing is not None and "publishedSource" in existing.input) or (
                        existing is None and initial is not None
                        and initial.status == "succeeded"
                        and initial.input.get("phase") == "completed")
                    if published:
                        source = None
                        if existing is None:
                            snapshot = _current_scope_snapshot(
                                core, jobs=jobs, chains=SqlAlchemySketchChainRepository(),
                                resources=SqlAlchemyProviderResourceRepository(),
                                inspector_state_reader=None, state_root=state_root,
                            )
                            if snapshot.get("snapshotId") != body.get("snapshotId"):
                                raise PublishedKeyedDispatchAttention(
                                    "reviewed teardown scope changed")
                            source = require_prequeue_published_generation(
                                core, snapshot, environment="devtest", state_root=state_root,
                                job_repository=jobs,
                            )
                        job = start_engagement_teardown(
                            job_id, body, provider_keyed_environment="devtest",
                            provider_keyed_published_source=source,
                            provider_keyed_state_root=state_root,
                            provider_keyed_coordinator=(
                                (lambda parent_id: run_provider_keyed_comprehensive_handoff(
                                    parent_id, environment="devtest", state_root=state_root))
                                if existing is None else (lambda _parent_id: jobs.get(_child_id(core.id)))
                            ),
                        )
                        if existing is None and job is not None and job.status == "queued":
                            from app.core.runtime import start_runtime_task
                            start_runtime_task(
                                lambda: advance_published_keyed_terminal(
                                    job.id, environment="devtest", state_root=state_root,
                                    positive_control_ipv4=control,
                                ), name="barragan-keyed-published-teardown",
                            )
                        elif existing is not None and job is not None and job.status == "queued":
                            from app.core.runtime import start_runtime_task
                            from app.services.provider_keyed_published_dispatch import (
                                recover_published_keyed_dispatches,
                            )
                            eligible = {}
                            recover_published_keyed_dispatches(
                                environment="devtest", state_root=state_root,
                                positive_control_ipv4=control,
                                schedule=lambda candidate, delay: eligible.update(
                                    {candidate: delay}),
                            )
                            if job.id in eligible:
                                delay = eligible[job.id]

                                def resume_published() -> None:
                                    if delay:
                                        from threading import Event
                                        Event().wait(delay)
                                    current = {}
                                    recover_published_keyed_dispatches(
                                        environment="devtest", state_root=state_root,
                                        positive_control_ipv4=control,
                                        schedule=lambda candidate, remaining: current.update(
                                            {candidate: remaining}),
                                    )
                                    if current.get(job.id) == 0.0:
                                        advance_published_keyed_terminal(
                                            job.id, environment="devtest", state_root=state_root,
                                            positive_control_ipv4=control,
                                        )

                                start_runtime_task(
                                    resume_published,
                                    name="barragan-keyed-published-teardown-recovery",
                                )
                        return {"job": job.to_detail().to_dict()}
                    if existing is None:
                        snapshot = _current_scope_snapshot(
                            core, jobs=jobs, chains=SqlAlchemySketchChainRepository(),
                            resources=SqlAlchemyProviderResourceRepository(),
                            inspector_state_reader=None,
                        )
                        if snapshot.get("snapshotId") != body.get("snapshotId"):
                            raise PendingKeyedDispatchAttention("reviewed teardown scope changed")
                        require_prequeue_pending_diagnostic(
                            core, snapshot, environment="devtest", state_root=state_root,
                            job_repository=jobs,
                        )
                    else:
                        parent, saved_core, snapshot, operation = _boundary(
                            existing.id, jobs, SqlAlchemyDeploymentPlanRepository(), _db_lease_lookup)
                        if saved_core.id != core.id or "publishedSource" in parent.input:
                            raise PendingKeyedDispatchAttention("pending teardown source differs")
                        _require_diagnostic_scope(core, snapshot)
                        coordinator = jobs.get(_child_id(core.id))
                        if coordinator is not None and (
                                coordinator.action != "provider_keyed_comprehensive_teardown"
                                or coordinator.target_id != parent.target_id
                                or coordinator.input.get("teardownParentId") != parent.id
                                or coordinator.input.get("scopeSnapshotId") != snapshot["snapshotId"]
                                or coordinator.status not in {"queued", "running"}):
                            raise PendingKeyedDispatchAttention("pending teardown coordinator differs")
                        if operation == "provider_keyed_initial" and coordinator is None:
                            proof = load_keyed_teardown_source(
                                parent.id, phase="pre_handoff", environment="devtest",
                                state_root=state_root, job_repository=jobs,
                            )
                            expected = ("failed_prebinding"
                                        if snapshot.get("dnsCleanupManifest", {}).get("schema")
                                           == "provider-keyed-empty-dns-prebinding-v1"
                                        else "pending_terminal")
                            if proof.variant != expected:
                                raise PendingKeyedDispatchAttention("pending teardown source differs")
                        elif operation == "provider_keyed_teardown_fence" and coordinator is None:
                            raise PendingKeyedDispatchAttention("pending teardown coordinator is missing")
                    job = start_engagement_teardown(
                        job_id, body, provider_keyed_environment="devtest",
                        provider_keyed_coordinator=lambda parent_id: run_provider_keyed_comprehensive_handoff(
                            parent_id, environment="devtest", state_root=state_root,
                        ),
                    )
                    if job is not None and job.status == "queued":
                        from app.core.runtime import start_runtime_task
                        start_runtime_task(
                            lambda: advance_pending_keyed_terminal(
                                job.id, environment="devtest", state_root=state_root,
                                positive_control_ipv4=control,
                            ), name="barragan-keyed-pending-teardown",
                        )
                else:
                    job = start_engagement_teardown(job_id, body)
            except (EngagementWorkspaceValidationError, EngagementTeardownValidationError,
                    MixedZeroApplyDispatchAttention, MixedInterruptedDispatchAttention,
                    PublishedMixedDispatchAttention) as exc:
                return JSONResponse({"errors": getattr(exc, "errors", [str(exc)])}, status_code=400)
            except ValueError:
                return JSONResponse({"errors": ["pending keyed teardown source is unproved"]}, status_code=409)
            if job is None:
                raise HTTPException(status_code=404, detail="pilot run not found")
            return {"job": job.to_detail().to_dict()}

    @app.post("/api/orchestrator/barragan-testing/linode-sketch/runs")
    async def orchestrator_linode_sketch_runs_create(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                engagement_id = str(body.get("engagementId") or "").strip()
                if engagement_id:
                    assert_engagement_mutation_allowed(engagement_id)
                job = start_guarded_linode_sketch_run(body)
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except LinodeSketchGuardrailError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            return JSONResponse({"job": job.to_dict()}, status_code=201)

    @app.get("/api/orchestrator/barragan-testing/linode-sketch/runs/{job_id}")
    def orchestrator_linode_sketch_runs_show(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            job = get_guarded_linode_sketch_run(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="Linode sketch run not found")
            return {"job": job.to_dict()}

    @app.post("/api/orchestrator/barragan-testing/linode-sketch/runs/{job_id}/teardown")
    def orchestrator_linode_sketch_runs_teardown(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            job = teardown_guarded_linode_sketch_run(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="Linode sketch run not found")
            return {"job": job.to_dict()}

    @app.post("/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs")
    async def orchestrator_digitalocean_sketch_validation_runs_create(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                job = start_guarded_digitalocean_provider_validation_run(body)
            except DigitalOceanProviderValidationGuardrailError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            return JSONResponse({"job": job.to_dict()}, status_code=201)

    @app.get("/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs/{job_id}")
    def orchestrator_digitalocean_sketch_validation_runs_show(job_id: str) -> dict[str, Any]:
        with _storage_context(app):
            job = get_guarded_digitalocean_provider_validation_run(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="DigitalOcean provider-smoke run not found")
            return {"job": job.to_dict()}

    @app.get("/api/dashboard")
    def dashboard_show(live: str = "") -> dict[str, Any]:
        with _storage_context(app):
            return {"dashboard": get_dashboard_inventory(include_provider_reconciliation=_truthy(live))}

    @app.post("/api/dashboard/orphan-candidates/actions")
    async def dashboard_orphan_candidate_action(request: Request) -> JSONResponse:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = recover_provider_orphan_candidate(body)
            except ProviderOrphanRecoveryError as exc:
                payload: dict[str, Any] = {"errors": exc.errors}
                if exc.job is not None:
                    payload["job"] = exc.job.to_detail().to_dict()
                return JSONResponse(payload, status_code=exc.status_code)
            status_code = 202 if body.get("mutation") else 201
            return JSONResponse(result.to_dict(), status_code=status_code)

    @app.get("/api/credentials")
    def credentials_index(provider: str | None = None) -> dict[str, Any]:
        with _storage_context(app):
            return {"credentials": [credential.to_dict() for credential in list_credentials(provider=provider)]}

    @app.post("/api/credentials")
    async def credentials_create(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                credential = create_credential(body)
            except CredentialValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            return JSONResponse({"credential": credential.to_dict()}, status_code=201)

    @app.post("/api/credentials/{credential_id}/validate")
    def credentials_validate(credential_id: str) -> Any:
        with _storage_context(app):
            try:
                result = validate_credential(credential_id)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="credential not found")
            return {"validation": result.to_dict()}

    @app.patch("/api/credentials/{credential_id}")
    async def credentials_rotate(credential_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                credential = rotate_credential(credential_id, body)
            except CredentialValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if credential is None:
                raise HTTPException(status_code=404, detail="credential not found")
            return {"credential": credential.to_dict()}

    @app.delete("/api/credentials/{credential_id}")
    def credentials_delete(credential_id: str) -> dict[str, Any]:
        with _storage_context(app):
            credential = disable_credential(credential_id)
            if credential is None:
                raise HTTPException(status_code=404, detail="credential not found")
            return {"credential": credential.to_dict()}

    @app.post("/api/credentials/{credential_id}/default")
    def credentials_set_default(credential_id: str) -> dict[str, Any]:
        with _storage_context(app):
            credential = set_default_credential(credential_id)
            if credential is None:
                raise HTTPException(status_code=404, detail="active credential not found")
            return {"credential": credential.to_dict()}

    @app.get("/api/team")
    def team_index() -> dict[str, Any]:
        with _storage_context(app):
            return list_team_members()

    @app.post("/api/team")
    async def team_create(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = create_team_member(body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return JSONResponse(result, status_code=201)

    @app.post("/api/team/import/preview")
    async def team_import_preview(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_team_import(body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return result

    @app.post("/api/team/import/apply")
    async def team_import_apply(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = apply_team_import(body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return JSONResponse(result, status_code=202)

    @app.patch("/api/team/{member_id}")
    async def team_update(member_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_team_member(member_id, body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="team member not found")
            return result

    @app.post("/api/team/{member_id}/deactivate")
    def team_deactivate(member_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = deactivate_team_member(member_id)
            if result is None:
                raise HTTPException(status_code=404, detail="team member not found")
            return result

    @app.post("/api/team/{member_id}/ssh-keys")
    async def team_ssh_key_create(member_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = add_team_member_ssh_key(member_id, body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="team member not found")
            return JSONResponse(result, status_code=201)

    @app.patch("/api/team/{member_id}/ssh-keys/{key_id}")
    async def team_ssh_key_update(member_id: str, key_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_team_member_ssh_key(member_id, key_id, body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="team member or SSH key not found")
            return result

    @app.delete("/api/team/{member_id}/ssh-keys/{key_id}")
    def team_ssh_key_delete(member_id: str, key_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = retire_team_member_ssh_key(member_id, key_id)
            if result is None:
                raise HTTPException(status_code=404, detail="team member or SSH key not found")
            return result

    @app.get("/api/engagements")
    def engagements_index(scope: str = "") -> dict[str, Any]:
        with _storage_context(app):
            include_inactive = scope == "all"
            return {"engagements": [engagement.to_dict() for engagement in list_engagements(include_inactive=include_inactive)]}

    @app.post("/api/engagements")
    async def engagements_create(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                engagement = create_draft_engagement(body)
                # Metadata-only creation is the durable-workspace entrypoint.
                # It deliberately does not validate topology or render IaC.
                if not body.get("templateId"):
                    prepared = prepare_engagement_workspace(
                        engagement.id,
                        root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                    )
                    if prepared is None:
                        raise EngagementWorkspaceValidationError(["engagement workspace could not be prepared"])
            except (EngagementValidationError, EngagementWorkspaceValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return JSONResponse({"engagement": engagement.to_dict()}, status_code=201)

    @app.get("/api/engagements/{engagement_id}")
    def engagements_show(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            engagement = get_engagement(engagement_id)
            if engagement is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"engagement": engagement.to_dict()}

    @app.post("/api/engagements/{engagement_id}/lifecycle/reconcile")
    def engagements_lifecycle_reconcile(engagement_id: str) -> Any:
        with _storage_context(app):
            engagement = get_engagement(engagement_id)
            if engagement is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            result = reconcile_engagement_lifecycle(
                engagement_id,
                administrative_status=engagement.status,
            )
            return {"reconciliation": result}

    @app.get("/api/engagements/{engagement_id}/workspace")
    def engagements_workspace_show(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                result = get_engagement_workspace(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except EngagementWorkspaceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/workspace")
    def engagements_workspace_prepare(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                result = prepare_engagement_workspace(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except EngagementWorkspaceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result.to_dict(), status_code=201 if result.created else 200)

    @app.post("/api/engagements/{engagement_id}/workspace/capability-lock")
    def engagements_workspace_capability_lock_render(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                result = render_capability_lock(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except EngagementWorkspaceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"render": result.to_dict()}

    @app.get("/api/engagements/{engagement_id}/capabilities")
    def engagements_capabilities_show(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                result = engagement_capability_workspace(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except EngagementWorkspaceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"capabilities": result}

    @app.patch("/api/engagements/{engagement_id}/capabilities")
    async def engagements_capabilities_update(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_engagement_capability_selection(
                    engagement_id,
                    body,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                    core_provider=engagement_core_provider(get_engagement(engagement_id)),
                )
            except (EngagementWorkspaceValidationError, EngagementCapabilityValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"capabilities": result}

    @app.get("/api/engagements/{engagement_id}/capabilities/reconciliation")
    def engagements_capabilities_reconciliation_show(engagement_id: str) -> Any:
        with _storage_context(app):
            result = get_capability_reconciliation(
                engagement_id,
                engagement_repos_root=Path(
                    getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")
                ),
            )
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"reconciliation": result}

    @app.post("/api/engagements/{engagement_id}/capabilities/reconciliation")
    async def engagements_capabilities_reconciliation_start(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_capability_reconciliation(
                    engagement_id,
                    engagement_repos_root=Path(
                        getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")
                    ),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except (
                CapabilityReconciliationValidationError,
                CapabilityRoleApplyPlanValidationError,
                EngagementWorkspaceValidationError,
            ) as exc:
                errors = getattr(exc, "errors", [str(exc)])
                return JSONResponse({"errors": errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse({"reconciliation": result}, status_code=202)

    @app.post("/api/engagements/{engagement_id}/capabilities/apply")
    async def engagements_capabilities_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_capability_apply(
                    engagement_id,
                    engagement_repos_root=Path(
                        getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")
                    ),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except (
                CapabilityApplyValidationError,
                CapabilityReconciliationValidationError,
                CapabilityRoleApplyPlanValidationError,
                EngagementCapabilityValidationError,
                EngagementWorkspaceValidationError,
                LegacyHomebaseRoleServiceValidationError,
            ) as exc:
                return JSONResponse({"errors": getattr(exc, "errors", [str(exc)])}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse({"capabilityApply": result}, status_code=202)

    @app.patch("/api/engagements/{engagement_id}")
    async def engagements_update(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                engagement = update_engagement_metadata(engagement_id, body)
            except EngagementValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if engagement is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"engagement": engagement.to_dict()}

    @app.delete("/api/engagements/{engagement_id}")
    def engagements_delete(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                engagement = retire_engagement(engagement_id)
            except ActiveInfrastructureError as exc:
                return JSONResponse(
                    {
                        "error": str(exc),
                        "activeInfrastructure": {
                            "jobId": exc.job_id,
                            "orphanCandidates": exc.orphan_candidates,
                            "providerRecords": exc.provider_records,
                            "lifecycle": exc.lifecycle,
                        },
                    },
                    status_code=409,
                )
            if engagement is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"engagement": engagement.to_dict()}

    @app.post("/api/engagements/{engagement_id}/archive")
    def engagements_archive(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                engagement = archive_engagement(engagement_id)
            except ActiveInfrastructureError as exc:
                return JSONResponse(
                    {
                        "error": str(exc),
                        "activeInfrastructure": {
                            "jobId": exc.job_id,
                            "orphanCandidates": exc.orphan_candidates,
                            "providerRecords": exc.provider_records,
                            "lifecycle": exc.lifecycle,
                        },
                    },
                    status_code=409,
                )
            if engagement is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"engagement": engagement.to_dict()}

    @app.get("/api/engagements/{engagement_id}/team")
    def engagements_team_index(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = get_engagement_team(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/team")
    async def engagements_team_enroll(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = enroll_engagement_member(engagement_id, body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.patch("/api/engagements/{engagement_id}/team/{membership_id}")
    async def engagements_team_update(engagement_id: str, membership_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_engagement_membership(engagement_id, membership_id, body)
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement team membership not found")
            return result

    @app.delete("/api/engagements/{engagement_id}/team/{membership_id}")
    def engagements_team_remove(engagement_id: str, membership_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = remove_engagement_membership(engagement_id, membership_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement team membership not found")
            return result

    @app.post("/api/engagements/{engagement_id}/team/access-plan")
    def engagements_team_access_plan(engagement_id: str) -> Any:
        with _storage_context(app):
            result = preview_engagement_access_plan(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/team/access-apply")
    async def engagements_team_access_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_engagement_access_apply(
                    engagement_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except TeamAccessValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/operations")
    def engagements_operations_show(engagement_id: str, live: str = "", includeProviderFindings: str = "") -> dict[str, Any]:
        with _storage_context(app):
            overview = get_operations_overview(
                engagement_id,
                include_provider_findings=_truthy(live) or _truthy(includeProviderFindings),
            )
            if overview is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"operations": overview}

    @app.patch("/api/engagements/{engagement_id}/operations")
    async def engagements_operations_update(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                overview = update_operations_overview(engagement_id, body)
            except EngagementOperationsValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if overview is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"operations": overview}

    @app.post("/api/engagements/{engagement_id}/infrastructure")
    async def engagements_configure_infrastructure(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                engagement = configure_engagement_infrastructure(engagement_id, body)
            except EngagementValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if engagement is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"engagement": engagement.to_dict()}

    @app.get("/api/domains")
    def domains_index() -> dict[str, Any]:
        with _storage_context(app):
            return {"domains": list_domain_groups()}

    @app.get("/api/domains/purposes")
    def domains_purposes() -> dict[str, Any]:
        with _storage_context(app):
            return {"purposes": list_domain_purposes()}

    @app.post("/api/domains/sync/namecheap")
    async def domains_namecheap_sync(request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = sync_namecheap_domains(body)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            status_code = 201 if result["job"]["status"] == "succeeded" else 400
            return JSONResponse(result, status_code=status_code)

    @app.get("/api/domains/{domain_id}")
    def domains_show(domain_id: str) -> dict[str, Any]:
        with _storage_context(app):
            domain = get_domain_detail(domain_id)
            if domain is None:
                raise HTTPException(status_code=404, detail="domain not found")
            return {"domain": domain}

    @app.get("/api/domains/{domain_id}/hosts")
    def domains_hosts(domain_id: str) -> dict[str, Any]:
        with _storage_context(app):
            hosts = get_cached_hosts(domain_id)
            if hosts is None:
                raise HTTPException(status_code=404, detail="domain not found")
            return {"hosts": hosts.to_dict()}

    @app.post("/api/domains/{domain_id}/assign")
    async def domains_assign(domain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = assign_domain(domain_id, body)
            except DomainNotFoundError:
                raise HTTPException(status_code=404, detail="domain not found") from None
            except DomainConfirmationRequired as exc:
                return JSONResponse({"confirmationRequired": exc.to_dict()}, status_code=409)
            except DomainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return result

    @app.post("/api/domains/{domain_id}/release")
    async def domains_release(domain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = release_domain(domain_id, body)
            except DomainNotFoundError:
                raise HTTPException(status_code=404, detail="domain not found") from None
            except DomainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return result

    @app.patch("/api/domains/{domain_id}/assignment")
    async def domains_assignment_patch(domain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = patch_domain_assignment(domain_id, body)
            except DomainNotFoundError:
                raise HTTPException(status_code=404, detail="domain not found") from None
            except DomainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return result

    @app.patch("/api/domains/{domain_id}/catalog-state")
    async def domains_catalog_state_patch(domain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                domain = patch_domain_catalog_state(domain_id, body)
            except DomainNotFoundError:
                raise HTTPException(status_code=404, detail="domain not found") from None
            except DomainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return {"domain": domain}

    @app.patch("/api/domains/{domain_id}/risk")
    async def domains_risk_patch(domain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                domain = patch_domain_risk(domain_id, body)
            except DomainNotFoundError:
                raise HTTPException(status_code=404, detail="domain not found") from None
            except DomainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return {"domain": domain}

    @app.get("/api/engagements/{engagement_id}/domains")
    def engagements_domains_index(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            if get_engagement(engagement_id) is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"domains": list_engagement_domains(engagement_id)}

    @app.get("/api/engagements/{engagement_id}/dns")
    def engagements_dns_index(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            workspace = get_engagement_dns_workspace(engagement_id)
            if workspace is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"dns": workspace}

    @app.post("/api/engagements/{engagement_id}/dns/preview")
    async def engagements_dns_preview(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                preview = preview_engagement_dns(engagement_id, body)
            except EngagementDnsValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if preview is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse({"preview": preview}, status_code=201)

    @app.post("/api/engagements/{engagement_id}/dns/apply")
    async def engagements_dns_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_engagement_dns_apply(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except EngagementDnsValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/revisions")
    def engagements_revisions_index(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            return {"revisions": list_revisions(engagement_id)}

    @app.post("/api/engagements/{engagement_id}/revisions")
    def engagements_revisions_create(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                revision = create_revision(engagement_id)
            except RevisionNotFoundError:
                raise HTTPException(status_code=404, detail="engagement not found") from None
            except RevisionCompileError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            return JSONResponse({"revision": revision}, status_code=201)

    @app.get("/api/revisions/{revision_id}")
    def revisions_show(revision_id: str) -> dict[str, Any]:
        with _storage_context(app):
            revision = get_revision(revision_id)
            if revision is None:
                raise HTTPException(status_code=404, detail="revision not found")
            return {"revision": revision}

    @app.post("/api/revisions/{revision_id}/render")
    async def revisions_render(revision_id: str, request: Request) -> Any:
        body = await _json_body(request)
        destination = Path(body.get("renderDestination", "/tmp/barragan-render-api"))
        render_job_id = body.get("renderJobId")
        with _storage_context(app):
            try:
                result = render_stored_revision(
                    revision_id,
                    destination,
                    render_job_id=str(render_job_id) if render_job_id else None,
                )
            except RevisionRenderNotFoundError:
                raise HTTPException(status_code=404, detail="revision not found") from None
            return {"renderResult": result.to_dict()}

    @app.post("/api/engagements/{engagement_id}/outbound-channels/{chain_id}/apply-preview")
    async def engagements_outbound_channel_apply_preview(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_outbound_channel_apply(
                    engagement_id,
                    chain_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except OutboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/outbound-channels/{chain_id}/apply")
    async def engagements_outbound_channel_apply(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = apply_outbound_channel(
                    engagement_id,
                    chain_id,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except OutboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/outbound-channels/{chain_id}/validate")
    async def engagements_outbound_channel_validate(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = validate_outbound_channel(
                    engagement_id,
                    chain_id,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except OutboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.delete("/api/engagements/{engagement_id}/outbound-channels/{chain_id}")
    async def engagements_outbound_channel_remove(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = remove_outbound_channel(
                    engagement_id,
                    chain_id,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except OutboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/apply-preview")
    async def engagements_inbound_channel_apply_preview(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_inbound_channel_apply(
                    engagement_id,
                    channel_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/inbound-channels")
    async def engagements_inbound_channel_create_and_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = create_and_apply_inbound_channel(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channel-batches/preview")
    async def engagements_inbound_channel_batch_preview(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_inbound_channel_batch(
                    engagement_id,
                    body.get("submissionId"),
                    body.get("channels"),
                )
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=200)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/prepare")
    async def engagements_inbound_channel_prepare(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = prepare_reviewed_inbound_channel(
                    engagement_id,
                    body.get("submissionId"),
                    body.get("previewFingerprint"),
                    body.get("channel"),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InboundChannelBatchConflictError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.get("/api/engagements/{engagement_id}/inbound-channel-batches/latest")
    def engagements_inbound_channel_batch_latest(engagement_id: str) -> Any:
        with _storage_context(app):
            result = latest_inbound_channel_batch(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/inbound-channel-batches")
    async def engagements_inbound_channel_batch_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_inbound_channel_batch(
                    engagement_id,
                    body.get("submissionId"),
                    body.get("previewFingerprint"),
                    body.get("channels"),
                )
            except InboundChannelBatchConflictError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channel-batches/{batch_id}/retry")
    async def engagements_inbound_channel_batch_retry(engagement_id: str, batch_id: str, _request: Request) -> Any:
        with _storage_context(app):
            try:
                result = retry_inbound_channel_batch(engagement_id, batch_id)
            except InboundChannelBatchConflictError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/apply")
    async def engagements_inbound_channel_apply(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_inbound_channel_apply(
                    engagement_id,
                    channel_id,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                    auto_validate=True,
                )
            except InboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/validate")
    async def engagements_inbound_channel_validate(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = validate_inbound_channel(
                    engagement_id,
                    channel_id,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/recover")
    async def engagements_inbound_channel_recover(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = recover_inbound_channel(
                    engagement_id,
                    channel_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except (InboundChannelWorkflowValidationError, InboundChannelApplyValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/managed-runtime")
    def engagements_inbound_channel_managed_runtime(engagement_id: str, channel_id: str) -> Any:
        with _storage_context(app):
            try:
                result = get_inbound_managed_runtime(engagement_id, channel_id)
            except InboundManagedRuntimeNotFoundError:
                raise HTTPException(status_code=404, detail="inbound channel not found")
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.get("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/request-header-gate")
    def engagements_inbound_channel_request_header_gate(engagement_id: str, channel_id: str) -> Any:
        with _storage_context(app):
            try:
                result = get_inbound_request_header_gate(
                    engagement_id,
                    channel_id,
                    engagement_root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except InboundRequestHeaderGateValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.put("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/request-header-gate")
    async def engagements_inbound_channel_request_header_gate_update(
        engagement_id: str,
        channel_id: str,
        request: Request,
    ) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_inbound_request_header_gate(
                    engagement_id,
                    channel_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                    engagement_root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
            except InboundRequestHeaderGateValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate")
    def engagements_inbound_channel_certificate(engagement_id: str, channel_id: str) -> Any:
        with _storage_context(app):
            try:
                result = channel_certificate_binding_workspace(engagement_id, channel_id)
                legacy = certificate_workspace(engagement_id, channel_id)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except InboundChannelCertificateValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            if legacy:
                result["prerequisites"] = legacy["prerequisites"]
            return result

    @app.get("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate-binding")
    def engagements_inbound_channel_certificate_binding(engagement_id: str, channel_id: str) -> Any:
        with _storage_context(app):
            try:
                result = channel_certificate_binding_workspace(engagement_id, channel_id)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.patch("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate-binding")
    async def engagements_inbound_channel_certificate_binding_update(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = bind_certificate_to_channel(engagement_id, channel_id, str(body.get("certificateId") or ""))
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.delete("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate-binding")
    def engagements_inbound_channel_certificate_binding_delete(engagement_id: str, channel_id: str) -> Any:
        with _storage_context(app):
            try:
                result = unbind_certificate_from_channel(engagement_id, channel_id)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.get("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate/prerequisites")
    def engagements_inbound_channel_certificate_prerequisites(engagement_id: str, channel_id: str) -> Any:
        with _storage_context(app):
            try:
                result = certificate_workspace(engagement_id, channel_id)
            except InboundChannelCertificateValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"prerequisites": result["prerequisites"], "channel": result["channel"]}

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate/challenge-channel")
    async def engagements_inbound_channel_certificate_challenge_channel(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = auto_configure_http01_channel(
                    engagement_id,
                    channel_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except (InboundChannelCertificateValidationError, InboundChannelWorkflowValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate/issue")
    async def engagements_inbound_channel_certificate_issue(engagement_id: str, channel_id: str, request: Request) -> Any:
        return await _inbound_channel_certificate_lifecycle_response(app, issue_certificate, engagement_id, channel_id, request)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate/renew")
    async def engagements_inbound_channel_certificate_renew(engagement_id: str, channel_id: str, request: Request) -> Any:
        return await _inbound_channel_certificate_lifecycle_response(app, renew_certificate, engagement_id, channel_id, request)

    @app.post("/api/engagements/{engagement_id}/inbound-channels/{channel_id}/certificate/revoke")
    async def engagements_inbound_channel_certificate_revoke(engagement_id: str, channel_id: str, request: Request) -> Any:
        return await _inbound_channel_certificate_lifecycle_response(app, revoke_certificate, engagement_id, channel_id, request)

    @app.delete("/api/engagements/{engagement_id}/inbound-channels/{channel_id}")
    async def engagements_inbound_channel_remove(engagement_id: str, channel_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = remove_inbound_channel(
                    engagement_id,
                    channel_id,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InboundChannelApplyValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/capabilities/backflips/apply-preview")
    @app.post("/api/engagements/{engagement_id}/services/backflips/apply-preview", deprecated=True)
    async def engagements_backflips_apply_preview(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_backflips_service_apply(
                    engagement_id,
                    proxy_id=str(body.get("proxyId") or "proxy01"),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except BackflipsServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/capabilities/backflips/apply")
    @app.post("/api/engagements/{engagement_id}/services/backflips/apply", deprecated=True)
    async def engagements_backflips_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = apply_backflips_service(
                    engagement_id,
                    proxy_id=str(body.get("proxyId") or "proxy01"),
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except BackflipsServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/services/legacy-homebase-roles")
    def engagements_legacy_homebase_role_services_catalog(engagement_id: str) -> Any:
        with _storage_context(app):
            if get_engagement(engagement_id) is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return list_legacy_homebase_role_catalog()

    @app.post("/api/engagements/{engagement_id}/services/legacy-homebase-roles/{role_slug}/apply-preview")
    async def engagements_legacy_homebase_role_apply_preview(engagement_id: str, role_slug: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_legacy_homebase_role_service_apply(
                    engagement_id,
                    role_slug,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except LegacyHomebaseRoleServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/services/legacy-homebase-roles/{role_slug}/apply")
    async def engagements_legacy_homebase_role_apply(engagement_id: str, role_slug: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = apply_legacy_homebase_role_service(
                    engagement_id,
                    role_slug,
                    confirmation=str(body.get("confirmation") or ""),
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except LegacyHomebaseRoleServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/capabilities/desktop")
    @app.get("/api/engagements/{engagement_id}/services/desktop", deprecated=True)
    def engagements_desktop_service_catalog(engagement_id: str) -> Any:
        with _storage_context(app):
            if get_engagement(engagement_id) is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return list_desktop_service_catalog()

    @app.post("/api/engagements/{engagement_id}/services/desktop/apply-preview", deprecated=True)
    async def engagements_desktop_service_apply_preview(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_desktop_service_apply(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except LegacyHomebaseRoleServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/services/desktop/apply", deprecated=True)
    async def engagements_desktop_service_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = apply_desktop_service(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except LegacyHomebaseRoleServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/capabilities/desktop/apply-preview")
    async def engagements_desktop_capability_apply_preview(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                resolved = desktop_capability_reconciliation_input(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
                if resolved is None:
                    raise HTTPException(status_code=404, detail="engagement not found")
                desired_apps, _source = resolved
                result = preview_desktop_service_apply(
                    engagement_id,
                    desired_apps,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except (EngagementWorkspaceValidationError, EngagementCapabilityValidationError, LegacyHomebaseRoleServiceValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/capabilities/desktop/apply")
    async def engagements_desktop_capability_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                resolved = desktop_capability_reconciliation_input(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
                if resolved is None:
                    raise HTTPException(status_code=404, detail="engagement not found")
                desired_apps, source = resolved
                result = apply_desktop_service(
                    engagement_id,
                    desired_apps,
                    requested_by=str(body.get("requestedBy") or "operator"),
                    desired_state_source=source,
                )
            except (EngagementWorkspaceValidationError, EngagementCapabilityValidationError, LegacyHomebaseRoleServiceValidationError) as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/capabilities/opsec-network-restrictions")
    @app.get("/api/engagements/{engagement_id}/services/opsec-network-restrictions", deprecated=True)
    def engagements_opsec_network_restrictions(engagement_id: str) -> Any:
        with _storage_context(app):
            result = get_opsec_network_restrictions(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/capabilities/opsec-network-restrictions/apply")
    @app.post("/api/engagements/{engagement_id}/services/opsec-network-restrictions/apply", deprecated=True)
    async def engagements_opsec_network_restrictions_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = apply_opsec_network_restrictions(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except OpsecNetworkRestrictionsValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/services")
    def engagements_services_index(engagement_id: str) -> Any:
        with _storage_context(app):
            result = list_web_static_services(engagement_id)
            generic_result = list_generic_services(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            result["services"] = [*result.get("services", []), *(generic_result or {}).get("services", [])]
            return result

    @app.get("/api/engagements/{engagement_id}/capabilities/static-web/sites")
    def engagements_web_static_sites_index(engagement_id: str) -> Any:
        with _storage_context(app):
            result = list_web_static_services(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.get("/api/engagements/{engagement_id}/capabilities/custom-listener/configurations")
    @app.get("/api/engagements/{engagement_id}/services/generic", deprecated=True)
    def engagements_generic_services_index(engagement_id: str) -> Any:
        with _storage_context(app):
            result = list_generic_services(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/capabilities/custom-listener/configurations")
    @app.post("/api/engagements/{engagement_id}/services/generic", deprecated=True)
    async def engagements_generic_services_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = create_generic_service(engagement_id, body)
            except GenericServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.patch("/api/engagements/{engagement_id}/capabilities/custom-listener/configurations/{service_id}")
    @app.patch("/api/engagements/{engagement_id}/services/generic/{service_id}", deprecated=True)
    async def engagements_generic_services_update(engagement_id: str, service_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_generic_service(engagement_id, service_id, body)
            except GenericServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/capabilities/custom-listener/configurations/{service_id}/disable")
    @app.post("/api/engagements/{engagement_id}/services/generic/{service_id}/disable", deprecated=True)
    def engagements_generic_services_disable(engagement_id: str, service_id: str) -> Any:
        with _storage_context(app):
            try:
                result = disable_generic_service(engagement_id, service_id)
            except GenericServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/capabilities/custom-listener/configurations/{service_id}/restore")
    @app.post("/api/engagements/{engagement_id}/services/generic/{service_id}/restore", deprecated=True)
    def engagements_generic_services_restore(engagement_id: str, service_id: str) -> Any:
        with _storage_context(app):
            try:
                result = restore_generic_service(engagement_id, service_id)
            except GenericServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.delete("/api/engagements/{engagement_id}/capabilities/custom-listener/configurations/{service_id}")
    @app.delete("/api/engagements/{engagement_id}/services/generic/{service_id}", deprecated=True)
    def engagements_generic_services_delete(engagement_id: str, service_id: str) -> Any:
        with _storage_context(app):
            try:
                result = remove_generic_service(engagement_id, service_id)
            except GenericServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/capabilities/static-web/sites/apply-preview")
    @app.post("/api/engagements/{engagement_id}/services/web-static/apply-preview", deprecated=True)
    async def engagements_web_static_apply_preview(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        # Remote content inspection must not block the ASGI event loop.
        def prepare_response() -> Any:
            with _storage_context(app):
                try:
                    result = preview_web_static_service_apply(
                        engagement_id,
                        body,
                        requested_by=str(body.get("requestedBy") or "operator"),
                    )
                except WebStaticServiceValidationError as exc:
                    return JSONResponse({"errors": exc.errors}, status_code=400)
                if result is None:
                    raise HTTPException(status_code=404, detail="engagement not found")
                capability_workspace = engagement_capability_workspace(
                    engagement_id,
                    root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                )
                static_state = ((capability_workspace or {}).get("nativeState") or {}).get("staticWeb") or {}
                workspace_prepared = bool((capability_workspace or {}).get("workspace"))
                result["capabilityPrerequisite"] = {
                    "ready": workspace_prepared,
                    "workspacePrepared": workspace_prepared,
                    "selected": bool(static_state.get("selected")),
                    "willSelectOnApply": workspace_prepared and not bool(static_state.get("selected")),
                    "reason": "" if workspace_prepared else "Prepare the engagement workspace before applying Static Web.",
                }
                return JSONResponse(result, status_code=201)

        return await run_in_threadpool(prepare_response)

    @app.post("/api/engagements/{engagement_id}/capabilities/static-web/sites")
    @app.post("/api/engagements/{engagement_id}/services/web-static/apply", deprecated=True)
    async def engagements_web_static_apply(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        # Remote content inspection must not block the ASGI event loop.
        def prepare_response() -> Any:
            with _storage_context(app):
                try:
                    result = start_web_static_service_apply(
                        engagement_id,
                        body,
                        requested_by=str(body.get("requestedBy") or "operator"),
                        before_start=lambda: ensure_static_web_capability_lock(
                            engagement_id,
                            root=Path(getattr(app.state.config, "ENGAGEMENT_REPOS_ROOT", "/opt/engagements")),
                        ),
                    )
                except (WebStaticServiceValidationError, EngagementCapabilityValidationError, EngagementWorkspaceValidationError) as exc:
                    return JSONResponse({"errors": exc.errors}, status_code=400)
                if result is None:
                    raise HTTPException(status_code=404, detail="engagement not found")
                return JSONResponse(result, status_code=202)

        return await run_in_threadpool(prepare_response)

    @app.post("/api/engagements/{engagement_id}/capabilities/static-web/sites/{service_id}/remove-preview")
    @app.post("/api/engagements/{engagement_id}/services/web-static/{service_id}/remove-preview", deprecated=True)
    async def engagements_web_static_remove_preview(engagement_id: str, service_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = preview_web_static_service_remove(
                    engagement_id,
                    service_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except WebStaticServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.delete("/api/engagements/{engagement_id}/capabilities/static-web/sites/{service_id}")
    @app.delete("/api/engagements/{engagement_id}/services/web-static/{service_id}", deprecated=True)
    async def engagements_web_static_remove(engagement_id: str, service_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_web_static_service_remove(
                    engagement_id,
                    service_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except WebStaticServiceValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/sketch-chains")
    def engagements_sketch_chains_index(engagement_id: str) -> Any:
        with _storage_context(app):
            chains = list_sketch_chains(engagement_id)
            if chains is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"sketchChains": chains}

    @app.post("/api/engagements/{engagement_id}/sketch-chains")
    async def engagements_sketch_chains_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                chain = create_sketch_chain(engagement_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if chain is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse({"sketchChain": chain}, status_code=201)

    @app.patch("/api/engagements/{engagement_id}/sketch-chains/{chain_id}")
    async def engagements_sketch_chains_update(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                chain = update_sketch_chain(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if chain is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return {"sketchChain": chain}

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/cancel")
    async def engagements_sketch_chains_cancel(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                chain = cancel_sketch_chain(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if chain is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return {"sketchChain": chain}

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/deploy")
    async def engagements_sketch_chains_deploy(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = deploy_sketch_chain(engagement_id, chain_id, body)
            except (SketchChainValidationError, LinodeSketchGuardrailError) as exc:
                errors = exc.errors if isinstance(exc, SketchChainValidationError) else [str(exc)]
                return JSONResponse({"errors": errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/retire")
    async def engagements_sketch_chain_retire_edge(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = retire_sketch_chain_final_edge(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/replace")
    async def engagements_sketch_chain_replace_edge(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = replace_sketch_chain_final_edge(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return JSONResponse(result, status_code=202)

    def append_edge_review(engagement_id: str, chain_id: str) -> dict[str, Any]:
        """Small redacted DevTest diagnostic; the saved plan never leaves the host."""
        from app.storage.job_repository import SqlAlchemyJobRepository
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
        from app.storage.engagement_repository import SqlAlchemyEngagementRepository
        from app.integrations.oci_deployment_targets import normalized_oci_deployment_target

        if getattr(app.state.config, "ENVIRONMENT", "") != "devtest":
            return {"available": False, "status": "unavailable"}
        engagement = SqlAlchemyEngagementRepository().get(engagement_id)
        try:
            target = normalized_oci_deployment_target(
                engagement.input_parameters.get("deploymentTarget")) if engagement else None
        except ValueError:
            target = None
        if target is None or target["name"] != "barragan-testing":
            return {"available": False, "status": "unavailable"}
        chain = SqlAlchemySketchChainRepository().get(engagement_id, chain_id)
        if chain is None:
            raise HTTPException(status_code=404, detail="sketch chain not found")
        jobs = SqlAlchemyJobRepository()
        initial = jobs.get(chain.deploy_job_id)
        if (engagement.sketch_state_schema != "provider-keyed-v2"
                or initial is None or initial.action != "provider_keyed_initial"
                or initial.status != "succeeded" or initial.target_id != engagement_id
                or initial.input.get("engagementId") != engagement_id
                or type(initial.input.get("coreJobId")) is not str):
            return {"available": False, "status": "unavailable"}
        related = jobs.list_for_engagement(engagement_id)
        parents = [job for job in related
                   if job.action == "provider_keyed_edge_append"]
        from app.services.provider_keyed_teardown_scope import (
            _reconciled_unapplied_append_state_sha,
        )
        active = [job for job in parents
                  if job.input.get("phase") != "unapplied_reconciled"]
        publication_recovery = ""
        if (len(active) == 1 and active[0].status == "failed"
                and active[0].input.get("phase") == "attention"
                and active[0].input.get("chainId") == chain_id):
            from app.services.provider_keyed_append_publication_recovery import (
                publication_recovery_state,
            )
            from app.services.sketch_state_workspaces import _default_state_root
            publication_recovery = publication_recovery_state(
                active[0].id, state_root=_default_state_root(), job_repository=jobs,
            )
        if (len(active) > 1 or (parents and not active and
                _reconciled_unapplied_append_state_sha(
                    engagement_id, jobs,
                    expected_core_job_id=initial.input["coreJobId"]) is None)
                or (active and len(parents) > 1 and
                    _reconciled_unapplied_append_state_sha(
                        engagement_id, jobs,
                        **({"allowed_published_parent_id": active[0].id}
                           if active[0].status == "succeeded" else
                           {"allowed_active_parent_id": active[0].id}),
                        expected_core_job_id=initial.input["coreJobId"]) is None)) and not publication_recovery:
            return {"available": False, "status": "attention"}
        parent = active[0] if active and active[0].input.get("chainId") == chain_id else None
        child = jobs.get(parent.input.get("planJobId")) if parent else None
        event = child.events[-1] if child and child.events else None
        reviewed = event.data if event and event.message == "reviewed append plan saved" else {}
        eligible = (chain.status == "deployed" and not chain.burned
                    and chain.middle_provider == "digitalocean"
                    and chain.edge_provider == "digitalocean"
                    and chain.edge_count == 1 and len(chain.nodes) == 2)
        failed_discard = ""
        failed_apply_recovery = ""
        if eligible and parent and child:
            from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

            failed_discard = _append_failed_review_discard_state(
                parent, child, related, jobs,
                lease=_db_lease_lookup(engagement_id),
                now=datetime.now(timezone.utc),
            )
            failed_apply_recovery = _append_no_go_recovery_state(
                parent, related, jobs,
                lease=_db_lease_lookup(engagement_id),
                now=datetime.now(timezone.utc),
            )
            unscheduled_cancel = _append_unscheduled_review_cancel_state(
                parent, child, jobs,
                lease=_db_lease_lookup(engagement_id),
                now=datetime.now(timezone.utc),
            )
        else:
            unscheduled_cancel = ""
        return {
            "available": bool((eligible and not active) or parent),
            "status": parent.input.get("phase", parent.status) if parent else "ready",
            "applyAvailable": bool(
                eligible and parent and parent.status == "running"
                and parent.input.get("phase") == "awaiting_apply"
                and parent.input.get("applyRequestedPlanSha256") is None
                and child and child.status == "succeeded"
                and getattr(app.state.config, "PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED", False) is True
            ),
            "applyRequested": bool(parent and parent.input.get("applyRequestedPlanSha256")),
            "failedReviewDiscardState": failed_discard,
            "failedApplyRecoveryState": failed_apply_recovery,
            "publicationRecoveryState": publication_recovery,
            "unscheduledReviewCancelState": unscheduled_cancel,
            "parentJobId": parent.id if parent else "",
            "planJobId": child.id if child else "",
            "planStatus": child.status if child else "",
            "newEdgeAddress": reviewed.get("newEdgeAddress", ""),
            "planSha256": reviewed.get("planSha256", ""),
        }

    @app.get("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/append/plan")
    def engagements_sketch_chain_append_plan_show(engagement_id: str, chain_id: str) -> Any:
        with _storage_context(app):
            return {"review": append_edge_review(engagement_id, chain_id)}

    def mixed_append_review_source(engagement_id: str) -> str | None:
        """Select only the published disposable two-chain mixed generation."""
        from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
        from app.services.provider_keyed_runtime_preflight import (
            ProviderKeyedRuntimePreflightError, reviewed_mixed_chain_rows,
        )
        from app.storage.engagement_repository import SqlAlchemyEngagementRepository
        from app.storage.job_repository import SqlAlchemyJobRepository
        from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository

        if getattr(app.state.config, "ENVIRONMENT", "") != "devtest":
            return None
        engagement = SqlAlchemyEngagementRepository().get(engagement_id)
        try:
            target = normalized_oci_deployment_target(
                engagement.input_parameters.get("deploymentTarget")) if engagement else None
        except ValueError:
            target = None
        if (engagement is None or target is None or target["name"] != "barragan-testing"
                or engagement.sketch_state_schema != "provider-keyed-v2"):
            return None
        chains = SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)
        deployment_ids = {chain.deploy_job_id for chain in chains if chain.deploy_job_id}
        if len(deployment_ids) != 1:
            return None
        initial_id = next(iter(deployment_ids))
        initial = SqlAlchemyJobRepository().get(initial_id)
        if (initial is None or initial.action != "provider_keyed_mixed_initial"
                or initial.status != "succeeded" or initial.target_id != engagement_id
                or initial.input.get("phase") != "completed"):
            return None
        try:
            chains = reviewed_mixed_chain_rows(
                chains, initial.input.get("chainIds"), engagement_id)
        except ProviderKeyedRuntimePreflightError:
            return None
        if (any(chain.status != "deployed" or chain.burned
                                    or len(chain.nodes) != 2 or chain.edge_count != 1
                                    or chain.middle_provider != chain.edge_provider
                                    or chain.deploy_job_id != initial_id
                                    for chain in chains)
                or {chain.middle_provider for chain in chains}
                   != {"digitalocean", "linode"}):
            return None
        core_job_id = initial.input.get("coreJobId")
        return core_job_id if isinstance(core_job_id, str) and core_job_id else None

    def mixed_append_review(engagement_id: str) -> dict[str, Any]:
        from app.services.provider_keyed_mixed_append_pair_apply_child import (
            _child_id as first_apply_child_id,
        )
        from app.services.provider_keyed_mixed_append_second_apply_child import (
            _child_id as second_apply_child_id,
        )
        from app.services.provider_keyed_mixed_append_pair_host_proof import (
            _child_id as host_proof_child_id,
        )
        from app.services.provider_keyed_mixed_append_review_runtime import (
            mixed_append_review_status,
        )
        from app.storage.job_repository import SqlAlchemyJobRepository

        core_job_id = mixed_append_review_source(engagement_id)
        if core_job_id is None:
            return {"available": False, "status": "unavailable"}
        saved = mixed_append_review_status(engagement_id, core_job_id)
        if saved is None:
            return {"available": True, "status": "ready"}
        parent, child = saved
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        append_owned = _db_lease_lookup(engagement_id) == (parent.input.get("corePlanId"), "provider_keyed_mixed_append")
        from app.services.provider_keyed_mixed_append_review_runtime import mixed_append_retry_choices
        retry_choices = mixed_append_retry_choices(parent, child, jobs=SqlAlchemyJobRepository()) if append_owned else None
        terminal = child.events[-1] if child.events else None
        review_sha = (terminal.data.get("reviewSha256")
                      if child.status == "succeeded" and terminal is not None
                      and terminal.message == "mixed append pair plan reviewed" else "")
        apply_stage = ""
        attention = False
        proof_resume = False
        stopped_failure = False
        pristine_apply = False
        if parent.input.get("phase") == "apply_sealed":
            jobs = SqlAlchemyJobRepository()
            first = jobs.get(first_apply_child_id(parent.id))
            second = jobs.get(second_apply_child_id(parent.id))
            host = jobs.get(host_proof_child_id(parent.id))
            from app.services.provider_keyed_mixed_append_apply_runtime import mixed_append_proof_resume_available, mixed_append_pristine_apply_available
            pristine_apply = mixed_append_pristine_apply_available(parent, jobs=jobs)
            proof_resume = mixed_append_proof_resume_available(parent, jobs=jobs)
            attention = any(job is not None and job.status == "failed"
                            for job in (first, second, host)) or proof_resume
            if host is not None:
                apply_stage = "publishing new edges" if host.status == "succeeded" else "proving new edges"
            elif second is not None:
                apply_stage = ("proving new edges" if second.status == "succeeded"
                               else "waiting for provider proof" if len(getattr(second, "events", [])) == 8
                               else "applying second provider")
            elif first is not None:
                apply_stage = ("applying second provider" if first.status == "succeeded"
                               else "applying first provider")
            else:
                apply_stage = "approved; no provider command started"
            from app.services.provider_keyed_mixed_failed_second_append import stopped_second_failure_attention
            stopped_failure = stopped_second_failure_attention(parent, jobs)
            if stopped_failure:
                attention, proof_resume, retry_choices = True, False, None
                apply_stage = "provider Apply failed; cleanup review required"
        return {
            "available": True,
            "status": "attention" if stopped_failure else parent.input.get("phase", parent.status),
            "parentJobId": parent.id,
            "planJobId": child.id,
            "planStatus": child.status,
            "reviewSha256": review_sha,
            "reviewSummary": parent.input.get("reviewSummary") if review_sha else None,
            "retryAvailable": retry_choices is not None,
            "retryChoices": retry_choices,
            "applyStage": apply_stage,
            "proofResumeAvailable": proof_resume,
            "attention": attention,
            "applyAvailable": bool(append_owned and not stopped_failure and review_sha and parent.input.get("reviewSummary")
                                   and parent.status == "running"
                                   and (parent.input.get("phase") == "planning" or pristine_apply)),
        }

    @app.get("/api/engagements/{engagement_id}/sketch/mixed-append/review")
    def engagements_mixed_append_review_show(engagement_id: str) -> Any:
        with _storage_context(app):
            return {"review": mixed_append_review(engagement_id)}

    @app.post("/api/engagements/{engagement_id}/sketch/mixed-append/review")
    async def engagements_mixed_append_review_create(
        engagement_id: str, request: Request,
    ) -> Any:
        from app.core.runtime import start_runtime_task
        from app.services.provider_keyed_mixed_append_review_runtime import (
            MixedAppendReviewAttention, begin_mixed_append_review,
            mixed_append_review_status, run_mixed_append_review,
        )

        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
                core_job_id = mixed_append_review_source(engagement_id)
                body = await request.json()
                if (core_job_id is None or type(body) is not dict
                        or set(body) != {"choices"} or type(body["choices"]) is not dict):
                    raise MixedAppendReviewAttention("paired edge Review is unavailable")
                parent = begin_mixed_append_review(
                    engagement_id, core_job_id, body["choices"],
                    requested_by=str(getattr(getattr(request.state, "identity", None),
                                             "username", "devtest-operator")))
                saved = mixed_append_review_status(engagement_id, core_job_id)
                if saved is None:
                    raise MixedAppendReviewAttention("paired edge Review is missing")
                _, child = saved
                if child.status == "queued":
                    start_runtime_task(
                        lambda: run_mixed_append_review(parent.id),
                        name="barragan-mixed-append-review")
            except (MixedAppendReviewAttention, EngagementTeardownValidationError,
                    ValueError, TypeError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            return JSONResponse({"review": mixed_append_review(engagement_id)}, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch/mixed-append/apply")
    async def engagements_mixed_append_apply(
        engagement_id: str, request: Request,
    ) -> Any:
        from app.core.runtime import start_runtime_task
        from app.services.provider_keyed_mixed_append_apply_runtime import (
            run_mixed_append_apply, claim_mixed_append_proof_resume,
            mixed_append_pristine_apply_available,
        )
        from app.services.provider_keyed_mixed_append_pair_parent import (
            MixedAppendPairParentAttention, approve_mixed_append_pair,
        )
        from app.services.provider_keyed_mixed_append_plan_context import (
            MixedAppendPlanContextAttention, collect_mixed_append_pair_plan_context,
        )
        from app.services.provider_keyed_mixed_append_review_runtime import (
            MixedAppendReviewAttention, mixed_append_review_status,
        )

        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
                core_job_id = mixed_append_review_source(engagement_id)
                body = await request.json()
                if (core_job_id is None or type(body) is not dict
                        or set(body) != {"reviewSha256"}
                        or type(body["reviewSha256"]) is not str):
                    raise MixedAppendReviewAttention("paired edge Apply is unavailable")
                saved = mixed_append_review_status(engagement_id, core_job_id)
                if saved is None:
                    raise MixedAppendReviewAttention("paired edge Review is missing")
                parent, child = saved
                terminal = child.events[-1] if child.events else None
                from app.storage.job_repository import SqlAlchemyJobRepository
                pristine_apply = mixed_append_pristine_apply_available(parent, jobs=SqlAlchemyJobRepository())
                proof_resume = parent.input.get("phase") == "apply_sealed" and not pristine_apply
                if ((not proof_resume and not pristine_apply and parent.input.get("phase") != "planning") or child.status != "succeeded"
                        or terminal is None
                        or terminal.message != "mixed append pair plan reviewed"
                        or terminal.data != {"reviewSha256": body["reviewSha256"]}):
                    raise MixedAppendReviewAttention("paired edge review digest differs")
                if proof_resume:
                    from app.storage.job_repository import SqlAlchemyJobRepository
                    if body["reviewSha256"] != parent.input.get("reviewSha256"):
                        raise MixedAppendReviewAttention("proof resume review differs")
                    proof_claim = claim_mixed_append_proof_resume(parent, jobs=SqlAlchemyJobRepository())
                elif pristine_apply:
                    from app.services.provider_keyed_mixed_append_availability import require_reviewed_mixed_append_availability
                    if body["reviewSha256"] != parent.input.get("reviewSha256"):
                        raise MixedAppendReviewAttention("pristine Apply review differs")
                    require_reviewed_mixed_append_availability(parent, jobs=SqlAlchemyJobRepository())
                else:
                    context = collect_mixed_append_pair_plan_context(parent.id)
                    approve_mixed_append_pair(
                        parent.id, expected_review_sha256=body["reviewSha256"],
                        **context.approval_kwargs())
                start_runtime_task(
                    lambda: run_mixed_append_apply(parent.id, proof_resume_only=True, proof_resume_claim=proof_claim) if proof_resume else run_mixed_append_apply(parent.id),
                    name="barragan-mixed-append-apply")
            except (MixedAppendReviewAttention, MixedAppendPlanContextAttention,
                    MixedAppendPairParentAttention, EngagementTeardownValidationError,
                    ValueError, TypeError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            return JSONResponse({"review": mixed_append_review(engagement_id)}, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/append/plan")
    async def engagements_sketch_chain_append_plan_create(
        engagement_id: str, chain_id: str, request: Request,
    ) -> Any:
        from app.services.provider_keyed_append_plan_job import (
            ProviderKeyedAppendPlanJobError,
            begin_published_digitalocean_edge_append_plan,
            cancel_unscheduled_digitalocean_edge_append_plan,
            run_published_digitalocean_edge_append_plan,
        )
        from app.services.sketch_state_workspaces import _default_state_root
        from app.core.runtime import start_runtime_task

        if getattr(app.state.config, "ENVIRONMENT", "") != "devtest":
            raise HTTPException(status_code=404, detail="append review unavailable")
        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
                from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
                from app.storage.engagement_repository import SqlAlchemyEngagementRepository
                from app.storage.job_repository import SqlAlchemyJobRepository
                from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
                engagement = SqlAlchemyEngagementRepository().get(engagement_id)
                if (engagement is None or normalized_oci_deployment_target(
                        engagement.input_parameters.get("deploymentTarget"))["name"]
                        != "barragan-testing" or engagement.sketch_state_schema != "provider-keyed-v2"):
                    raise ProviderKeyedAppendPlanJobError("append review requires disposable Barragan testing")
                chain = SqlAlchemySketchChainRepository().get(engagement_id, chain_id)
                if chain is None:
                    raise HTTPException(status_code=404, detail="sketch chain not found")
                initial = SqlAlchemyJobRepository().get(chain.deploy_job_id)
                if (initial is None or initial.action != "provider_keyed_initial"
                        or initial.status != "succeeded" or initial.target_id != engagement_id
                        or initial.input.get("engagementId") != engagement_id
                        or type(initial.input.get("coreJobId")) is not str):
                    raise ProviderKeyedAppendPlanJobError("selected published chain has no core job")
                parent, child = begin_published_digitalocean_edge_append_plan(
                    initial.input["coreJobId"], chain_id, chain.edge_region, chain.edge_size,
                    requested_by=str(getattr(getattr(request.state, "identity", None),
                                             "username", "devtest-operator")),
                    state_root=_default_state_root(),
                )
            except (ProviderKeyedAppendPlanJobError, EngagementTeardownValidationError, ValueError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            try:
                start_runtime_task(
                    lambda: run_published_digitalocean_edge_append_plan(
                        child.id, state_root=_default_state_root()),
                    name="barragan-keyed-edge-append-plan",
                )
            except Exception:
                try:
                    cancel_unscheduled_digitalocean_edge_append_plan(
                        parent.id, state_root=_default_state_root())
                except Exception:
                    # A worker may already have started. Keep its job/lease
                    # visible and avoid guessing whether commands ran.
                    pass
                return JSONResponse({"error": "append review worker was not scheduled",
                                     "review": append_edge_review(engagement_id, chain_id)},
                                    status_code=503)
            return JSONResponse({"review": append_edge_review(engagement_id, chain_id)}, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/append/plan/discard")
    def engagements_sketch_chain_append_plan_discard(engagement_id: str, chain_id: str) -> Any:
        from app.services.provider_keyed_append_plan_job import (
            ProviderKeyedAppendPlanJobError, discard_reviewed_digitalocean_edge_append_plan,
            reconcile_interrupted_digitalocean_edge_append_plan,
            cancel_unscheduled_digitalocean_edge_append_plan,
        )
        from app.services.sketch_state_workspaces import _default_state_root
        from app.storage.deployment_plan_repository import DeploymentPlanConflictError
        from app.storage.job_repository import SqlAlchemyJobRepository

        if getattr(app.state.config, "ENVIRONMENT", "") != "devtest":
            raise HTTPException(status_code=404, detail="append review unavailable")
        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            parents = [job for job in SqlAlchemyJobRepository().list_for_engagement(engagement_id)
                       if job.action == "provider_keyed_edge_append"
                       and job.input.get("phase") != "unapplied_reconciled"
                       and job.input.get("chainId") == chain_id]
            if len(parents) != 1:
                raise HTTPException(status_code=404, detail="append review not found")
            try:
                review = append_edge_review(engagement_id, chain_id)
                if review.get("failedReviewDiscardState") == "ready":
                    reconcile_interrupted_digitalocean_edge_append_plan(
                        parents[0].id, state_root=_default_state_root())
                elif review.get("unscheduledReviewCancelState") == "ready":
                    cancel_unscheduled_digitalocean_edge_append_plan(
                        parents[0].id, state_root=_default_state_root())
                elif review.get("status") == "awaiting_apply":
                    discard_reviewed_digitalocean_edge_append_plan(
                        parents[0].id, state_root=_default_state_root())
                else:
                    raise ProviderKeyedAppendPlanJobError(
                        "append review is not ready for safe discard")
            except (ProviderKeyedAppendPlanJobError, DeploymentPlanConflictError,
                    EngagementTeardownValidationError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            return {"review": append_edge_review(engagement_id, chain_id)}

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/append/plan/recover-no-go")
    def engagements_sketch_chain_append_plan_recover_no_go(engagement_id: str, chain_id: str) -> Any:
        from app.storage.deployment_plan_repository import DeploymentPlanConflictError
        from app.services.provider_keyed_append_plan_job import (
            ProviderKeyedAppendPlanJobError, reconcile_no_go_digitalocean_edge_append_apply,
        )
        from app.services.sketch_state_workspaces import _default_state_root
        from app.storage.job_repository import SqlAlchemyJobRepository

        if getattr(app.state.config, "ENVIRONMENT", "") != "devtest":
            raise HTTPException(status_code=404, detail="append recovery unavailable")
        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
            except EngagementTeardownValidationError as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            parents = [job for job in SqlAlchemyJobRepository().list_for_engagement(engagement_id)
                       if job.action == "provider_keyed_edge_append"
                       and job.input.get("phase") in {"attention", "no_go_cleaning"}
                       and job.input.get("chainId") == chain_id]
            if len(parents) != 1:
                raise HTTPException(status_code=404, detail="append recovery not found")
            try:
                if append_edge_review(engagement_id, chain_id).get(
                        "failedApplyRecoveryState") != "ready":
                    raise ProviderKeyedAppendPlanJobError("append recovery is not ready")
                reconcile_no_go_digitalocean_edge_append_apply(
                    parents[0].id, state_root=_default_state_root())
            except (ProviderKeyedAppendPlanJobError, DeploymentPlanConflictError,
                    EngagementTeardownValidationError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            return {"review": append_edge_review(engagement_id, chain_id)}

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/append/plan/apply")
    async def engagements_sketch_chain_append_plan_apply(
        engagement_id: str, chain_id: str, request: Request,
    ) -> Any:
        from app.core.runtime import start_runtime_task
        from app.services.provider_keyed_append_dispatch import (
            ProviderKeyedAppendDispatchError,
            advance_approved_digitalocean_edge_append,
            approve_reviewed_digitalocean_edge_append,
        )
        from app.services.sketch_state_workspaces import _default_state_root

        if (getattr(app.state.config, "ENVIRONMENT", "") != "devtest"
                or getattr(app.state.config, "PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED", False) is not True):
            raise HTTPException(status_code=404, detail="append Apply unavailable")
        body = await _json_body(request)
        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
                review = append_edge_review(engagement_id, chain_id)
                if (review.get("applyAvailable") is not True
                        or not isinstance(body, dict)
                        or body.get("planSha256") != review.get("planSha256")
                        or set(body) != {"planSha256"}):
                    raise ProviderKeyedAppendDispatchError("reviewed append plan differs")
                actor = getattr(getattr(request.state, "identity", None), "username", None)
                if not isinstance(actor, str) or not actor:
                    raise ProviderKeyedAppendDispatchError("authenticated Apply operator is required")
                approved = approve_reviewed_digitalocean_edge_append(
                    review["parentJobId"], expected_plan_sha256=body["planSha256"],
                    requested_by=actor,
                    state_root=_default_state_root(),
                )
                if (approved.target_id != engagement_id
                        or approved.input.get("chainId") != chain_id):
                    raise ProviderKeyedAppendDispatchError("selected append parent differs")
            except (ProviderKeyedAppendDispatchError, EngagementTeardownValidationError,
                    ValueError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            try:
                start_runtime_task(
                    lambda: advance_approved_digitalocean_edge_append(
                        approved.id, environment="devtest", rollout_enabled=True,
                        state_root=_default_state_root()),
                    name="barragan-keyed-edge-append-apply",
                )
            except Exception:
                # The click is durable; startup recovery will resume it.
                return JSONResponse({"error": "approved append worker was not scheduled",
                                     "review": append_edge_review(engagement_id, chain_id)},
                                    status_code=503)
            return JSONResponse({"review": append_edge_review(engagement_id, chain_id)},
                                status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/edges/append/plan/recover-publication")
    def engagements_sketch_chain_append_publication_recover(
        engagement_id: str, chain_id: str,
    ) -> Any:
        from app.core.runtime import start_runtime_task
        from app.services.provider_keyed_append_dispatch import (
            advance_approved_digitalocean_edge_append,
        )
        from app.services.provider_keyed_append_publication_recovery import (
            rearm_sealed_append_publication,
        )
        from app.services.sketch_state_workspaces import _default_state_root

        if (getattr(app.state.config, "ENVIRONMENT", "") != "devtest"
                or getattr(app.state.config, "PROVIDER_KEYED_EDGE_APPEND_APPLY_ENABLED", False) is not True):
            raise HTTPException(status_code=404, detail="append publication recovery unavailable")
        with _storage_context(app):
            try:
                assert_engagement_mutation_allowed(engagement_id)
                review = append_edge_review(engagement_id, chain_id)
                if (review.get("publicationRecoveryState") != "ready"
                        or not review.get("parentJobId")):
                    raise ValueError("append publication recovery is not ready")
                parent = rearm_sealed_append_publication(
                    review["parentJobId"], state_root=_default_state_root(),
                )
                if (parent.target_id != engagement_id
                        or parent.input.get("chainId") != chain_id):
                    raise ValueError("selected append publication differs")
            except (EngagementTeardownValidationError, ValueError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=409)
            try:
                start_runtime_task(
                    lambda: advance_approved_digitalocean_edge_append(
                        parent.id, environment="devtest", rollout_enabled=True,
                        state_root=_default_state_root()),
                    name="barragan-keyed-edge-append-publication-recovery",
                )
            except Exception:
                # The exact publication-only re-arm is durable across restart.
                return JSONResponse({"error": "append publication worker was not scheduled",
                                     "review": append_edge_review(engagement_id, chain_id)},
                                    status_code=503)
            return JSONResponse({"review": append_edge_review(engagement_id, chain_id)},
                                status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/refresh")
    def engagements_sketch_chains_refresh(engagement_id: str, chain_id: str) -> Any:
        with _storage_context(app):
            result = refresh_sketch_chain_from_job(engagement_id, chain_id)
            if result is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return result

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/stop")
    async def engagements_sketch_chains_stop(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = stop_sketch_chain(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/start")
    async def engagements_sketch_chains_start(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_sketch_chain(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/sketch-chains/{chain_id}/teardown")
    async def engagements_sketch_chains_teardown(engagement_id: str, chain_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = ensure_sketch_chain_teardown(engagement_id, chain_id, body)
            except SketchChainValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="sketch chain not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/sketch-ssh-key")
    def engagements_sketch_ssh_key_show(engagement_id: str) -> Any:
        with _storage_context(app):
            key = get_sketch_ssh_key_metadata(engagement_id)
            if key is None:
                raise HTTPException(status_code=404, detail="sketch SSH key not found")
            return {"key": key.to_dict()}

    @app.post("/api/engagements/{engagement_id}/sketch-ssh-key")
    def engagements_sketch_ssh_key_create(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                key = ensure_sketch_ssh_key(engagement_id)
            except SketchSshKeyNotFoundError as exc:
                return JSONResponse({"error": str(exc)}, status_code=404)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            return JSONResponse({"key": key.to_dict()}, status_code=201)

    @app.get("/api/engagements/{engagement_id}/sketch-ssh-key/material")
    def engagements_sketch_ssh_key_material(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                key = retrieve_sketch_ssh_key(engagement_id)
            except (CredentialStoreLockedError, CredentialDecryptError) as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if key is None:
                raise HTTPException(status_code=404, detail="sketch SSH key not found")
            return {"keyMaterial": key.to_dict()}

    @app.post("/api/engagements/{engagement_id}/sketch-ssh-key/rotation-preview")
    def engagements_sketch_ssh_key_rotation_preview(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                rotation = preview_sketch_ssh_key_rotation(engagement_id)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if rotation is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"rotation": rotation}

    @app.post("/api/engagements/{engagement_id}/sketch-ssh-key/rotate")
    async def engagements_sketch_ssh_key_rotate(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = rotate_sketch_ssh_key(engagement_id, body)
            except SketchSshKeyRotationError as exc:
                return JSONResponse({"errors": exc.errors, "rotation": exc.plan}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/sketch-ssh-key/removal-preview")
    def engagements_sketch_ssh_key_removal_preview(engagement_id: str) -> Any:
        with _storage_context(app):
            try:
                removal = preview_sketch_ssh_key_removal(engagement_id)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if removal is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"removal": removal}

    @app.delete("/api/engagements/{engagement_id}/sketch-ssh-key")
    async def engagements_sketch_ssh_key_remove(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = remove_sketch_ssh_key(engagement_id, body)
            except SketchSshKeyRemovalError as exc:
                return JSONResponse({"errors": exc.errors, "removal": exc.plan}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.get("/api/engagements/{engagement_id}/inspector-settings")
    def engagements_inspector_settings_show(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = get_inspector_settings(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.patch("/api/engagements/{engagement_id}/inspector-settings")
    async def engagements_inspector_settings_update(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_inspector_settings(engagement_id, body)
            except InspectorSettingsValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.get("/api/engagements/{engagement_id}/inspections")
    def engagements_inspections_index(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = list_inspections(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/inspections")
    async def engagements_inspections_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_inspection(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InspectionValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inspector-readiness")
    async def engagements_inspector_readiness_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                readiness = ensure_continuous_inspector_ready(
                    engagement_id,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InspectorReadinessError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            return JSONResponse({"readiness": readiness}, status_code=202)

    @app.post("/api/engagements/{engagement_id}/inspector-cleanup-preview")
    def engagements_inspector_cleanup_preview(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            preview = preview_inspector_cleanup(engagement_id)
            if preview is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"preview": preview}

    @app.post("/api/engagements/{engagement_id}/inspector-cleanup")
    async def engagements_inspector_cleanup_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_inspector_cleanup(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except InspectorCleanupValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=409)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/observer-settings")
    def engagements_observer_settings_show(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = get_observer_settings(engagement_id)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.patch("/api/engagements/{engagement_id}/observer-settings")
    async def engagements_observer_settings_update(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_observer_settings(engagement_id, body)
            except ObserverSettingsValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.post("/api/engagements/{engagement_id}/observer-checks")
    async def engagements_observer_checks_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = start_observer_check(
                    engagement_id,
                    body,
                    requested_by=str(body.get("requestedBy") or "operator"),
                )
            except ObserverCheckValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            except CredentialStoreLockedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=503)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=202)

    @app.get("/api/engagements/{engagement_id}/certificate-profile")
    def engagements_certificate_profile(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            workspace = certificate_manager_workspace(engagement_id)
            if workspace is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"profile": workspace["profile"]}

    @app.patch("/api/engagements/{engagement_id}/certificate-profile")
    async def engagements_certificate_profile_update(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_certificate_profile(engagement_id, body)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return result

    @app.get("/api/engagements/{engagement_id}/certificates")
    def engagements_certificates(engagement_id: str) -> dict[str, Any]:
        with _storage_context(app):
            workspace = certificate_manager_workspace(engagement_id)
            if workspace is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return {"certificateManager": workspace}

    @app.post("/api/engagements/{engagement_id}/certificates")
    async def engagements_certificate_create(engagement_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = create_certificate_asset(engagement_id, body)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="engagement not found")
            return JSONResponse(result, status_code=201)

    @app.get("/api/engagements/{engagement_id}/certificates/{certificate_id}")
    def engagements_certificate_detail(engagement_id: str, certificate_id: str) -> dict[str, Any]:
        with _storage_context(app):
            result = get_certificate_asset(engagement_id, certificate_id)
            if result is None:
                raise HTTPException(status_code=404, detail="certificate not found")
            return result

    @app.patch("/api/engagements/{engagement_id}/certificates/{certificate_id}")
    async def engagements_certificate_update(engagement_id: str, certificate_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = update_certificate_asset_metadata(engagement_id, certificate_id, body)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="certificate not found")
            return result

    @app.post("/api/engagements/{engagement_id}/certificates/{certificate_id}/external-replacement")
    async def engagements_certificate_external_replacement(engagement_id: str, certificate_id: str, request: Request) -> Any:
        body = await _json_body(request)
        with _storage_context(app):
            try:
                result = replace_external_certificate(engagement_id, certificate_id, body)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="certificate not found")
            return JSONResponse(result, status_code=201)

    @app.post("/api/engagements/{engagement_id}/certificates/{certificate_id}/retire")
    def engagements_certificate_retire(engagement_id: str, certificate_id: str) -> Any:
        with _storage_context(app):
            try:
                result = retire_certificate_asset(engagement_id, certificate_id)
            except CertificateManagerValidationError as exc:
                return JSONResponse({"errors": exc.errors}, status_code=400)
            if result is None:
                raise HTTPException(status_code=404, detail="certificate not found")
            return result

    @app.post("/api/engagements/{engagement_id}/certificates/{certificate_id}/issue")
    async def engagements_certificate_issue(engagement_id: str, certificate_id: str, request: Request) -> Any:
        return await _certificate_lifecycle_response(app, start_certificate_issue, engagement_id, certificate_id, request)

    @app.post("/api/engagements/{engagement_id}/certificates/{certificate_id}/renew")
    async def engagements_certificate_renew(engagement_id: str, certificate_id: str, request: Request) -> Any:
        return await _certificate_lifecycle_response(app, start_certificate_renew, engagement_id, certificate_id, request)

    @app.post("/api/engagements/{engagement_id}/certificates/{certificate_id}/reissue")
    async def engagements_certificate_reissue(engagement_id: str, certificate_id: str, request: Request) -> Any:
        return await _certificate_lifecycle_response(app, start_certificate_reissue, engagement_id, certificate_id, request)

    @app.post("/api/engagements/{engagement_id}/certificates/{certificate_id}/revoke")
    async def engagements_certificate_revoke(engagement_id: str, certificate_id: str, request: Request) -> Any:
        return await _certificate_lifecycle_response(app, start_certificate_revoke, engagement_id, certificate_id, request)

    return app


def _append_unscheduled_review_cancel_state(
    parent: Any, child: Any, jobs: Any, *,
    lease: tuple[str, str] | None, now: datetime,
) -> str:
    """Offer cancellation only for an old reservation whose worker never claimed it."""
    from app.services.provider_keyed_append_plan_job import (
        _only_attested_historical_no_go_apply_children,
    )

    if (parent.status != "running" or parent.input.get("phase") != "planning"
            or parent.input.get("claimExpiresAt") is not None
            or parent.input.get("planJobId") != child.id
            or child.status != "queued" or getattr(child, "started_at", None) is not None
            or getattr(parent, "artifact_refs", []) or getattr(child, "artifact_refs", [])
            or len(getattr(parent, "events", [])) != 1
            or parent.events[0].message != "provider append review reserved"
            or len(getattr(child, "events", [])) != 1
            or child.events[0].message != "provider append plan queued"
            or lease != (parent.input.get("corePlanId"), "provider_keyed_edge_append")
            or not _only_attested_historical_no_go_apply_children(parent, jobs)):
        return ""
    try:
        created = datetime.fromisoformat(getattr(parent, "created_at", None))
    except (TypeError, ValueError):
        return ""
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return "ready" if now - created >= timedelta(minutes=1) else "waiting"


def _append_failed_review_discard_state(
    parent: Any, child: Any, related: list[Any], jobs: Any, *,
    lease: tuple[str, str] | None, now: datetime,
) -> str:
    """A redacted hint; the existing cleanup worker rechecks every artifact."""
    from app.services.provider_keyed_append_plan_job import (
        _only_attested_historical_no_go_apply_children,
    )
    if (parent.status != "running" or parent.action != "provider_keyed_edge_append"
            or parent.input.get("phase") != "planning"
            or parent.input.get("applyRequestedPlanSha256") is not None
            or child.action != "provider_keyed_edge_append_plan"
            or child.status != "failed"
            or parent.input.get("planJobId") != child.id
            or child.input.get("parentJobId") != parent.id
            or parent.input.get("engagementId") != parent.target_id
            or child.target_id != parent.target_id
            or lease != (parent.input.get("corePlanId"), "provider_keyed_edge_append")
            or not _only_attested_historical_no_go_apply_children(parent, jobs)):
        return ""
    expiry = parent.input.get("claimExpiresAt")
    if not isinstance(expiry, str):
        return ""
    try:
        due = datetime.fromisoformat(expiry)
    except ValueError:
        return ""
    if due.tzinfo is None or now.tzinfo is None:
        return ""
    return "ready" if now >= due else "waiting"


def _append_no_go_recovery_state(
    parent: Any, related: list[Any], jobs: Any, *,
    lease: tuple[str, str] | None, now: datetime,
) -> str:
    """A UI hint only; recovery re-proves state and journals under locks."""
    from app.services.provider_keyed_teardown_scope import _exact_no_go_apply_child

    if (parent.status != "failed"
            or parent.input.get("phase") not in {"attention", "no_go_cleaning"}
            or lease != (parent.input.get("corePlanId"), "provider_keyed_edge_append")
            or _exact_no_go_apply_child(parent, related, jobs,
                fenced=parent.input["phase"] == "no_go_cleaning") is None):
        return ""
    expiry = parent.input.get("claimExpiresAt")
    try:
        due = datetime.fromisoformat(expiry) if type(expiry) is str else None
    except ValueError:
        return ""
    if due is None or due.tzinfo is None:
        return ""
    return "ready" if now >= due else "waiting"


def _keyed_core_plan_deploy_eligible(config: type, plan: Any) -> bool:
    """Advertise only the reviewed, fresh DevTest pending-build diagnostic."""
    from app.services.provider_keyed_mixed_initial_public import is_reviewed_mixed_initial

    if is_reviewed_mixed_initial(plan):
        return _mixed_keyed_core_plan_deploy_eligible(config, plan)
    if (getattr(config, "ENVIRONMENT", "") != "devtest"
            or getattr(config, "PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED", False) is not True
            or plan.status != "ready" or plan.stage != "ready" or plan.apply_job_id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or plan.evidence.get("managedHostImageProfile") != "ubuntu-24.04"):
        return False
    evidence = plan.evidence
    authorization = evidence.get("sketchAuthorization")
    chains = authorization.get("chains") if isinstance(authorization, dict) else None
    reviewed_scope = plan.review.get("postCoreScope") if isinstance(plan.review, dict) else None
    counts = plan.review.get("counts") if isinstance(plan.review, dict) else None
    if (not isinstance(authorization, dict)
            or authorization.get("provider") != "digitalocean"
            or not isinstance(authorization.get("providerConnectionId"), str)
            or not authorization["providerConnectionId"]
            or not isinstance(evidence.get("keyedProviderCredentialSnapshot"), dict)
            or not isinstance(chains, list) or len(chains) != 2
            or any(not isinstance(row, dict)
                   or not isinstance(row.get("middle"), dict)
                   or row["middle"].get("provider") != "digitalocean"
                   or not isinstance(row.get("edges"), list) or not row["edges"]
                   or any(not isinstance(edge, dict)
                          or edge.get("provider") != "digitalocean" for edge in row["edges"])
                   for row in chains)
            or not isinstance(reviewed_scope, dict)
            or reviewed_scope.get("chainCount") != 2
            or not isinstance(counts, dict) or type(counts.get("add")) is not int
            or counts["add"] <= 0 or counts.get("replace", 0) != 0
            or counts.get("remove", 0) != 0):
        return False
    try:
        from app.services.core_deployment_plans import _verify_plan_evidence
        from app.services.guarded_test_deployment import (
            _require_configured_keyed_source, _target_for_engagement,
        )
        from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4

        require_positive_control_ipv4(
            getattr(config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
        engagement = get_engagement(plan.engagement_id)
        if (engagement is None or engagement.sketch_state_schema != "provider-keyed-v2"
                or engagement.active_revision != plan.revision_id
                or _target_for_engagement(engagement).name != "barragan-testing"
                or evidence.get("target", {}).get("name") != "barragan-testing"):
            return False
        source = _require_configured_keyed_source()
        if (authorization.get("source", {}).get("revision") != source["revision"]
                or authorization.get("source", {}).get("templateSha256") != source["templateSha256"]):
            return False
        _verify_plan_evidence(plan)
        return True
    except Exception:
        return False


def _mixed_keyed_core_plan_deploy_eligible(config: type, plan: Any) -> bool:
    """The mixed diagnostic stops at saved host-proof handoff, not publication."""
    if (getattr(config, "ENVIRONMENT", "") != "devtest"
            or getattr(config, "PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED", False) is not True
            or plan.status != "ready" or plan.stage != "ready" or plan.apply_job_id
            or plan.evidence.get("sketchStateSchema") != "provider-keyed-v2"
            or plan.evidence.get("managedHostImageProfile") != "ubuntu-24.04"):
        return False
    evidence = plan.evidence
    auth = evidence.get("sketchAuthorization")
    scopes = auth.get("providerScopes") if isinstance(auth, dict) else None
    reviewed = plan.review.get("reviewedConfiguration") if isinstance(plan.review, dict) else None
    counts = plan.review.get("counts") if isinstance(plan.review, dict) else None
    snapshots = evidence.get("keyedProviderCredentialSnapshots")
    if (not isinstance(scopes, list) or len(scopes) != 2
            or {scope.get("provider") for scope in scopes if isinstance(scope, dict)} !=
            {"linode", "digitalocean"}
            or not isinstance(snapshots, dict) or set(snapshots) != {"linode", "digitalocean"}
            or not isinstance(reviewed, dict) or reviewed.get("templateId") != "small-dev-infra"
            or reviewed.get("core") != {"homebases": 1, "proxies": 1, "elkEnabled": False}
            or not isinstance(counts, dict) or type(counts.get("add")) is not int
            or counts["add"] <= 0 or counts.get("replace") != 0 or counts.get("remove") != 0):
        return False
    try:
        from app.services.core_deployment_plans import _verify_plan_evidence
        from app.services.guarded_test_deployment import (
            _require_configured_keyed_source, _target_for_engagement,
        )
        from app.services.provider_keyed_pending_dispatch import require_positive_control_ipv4

        require_positive_control_ipv4(
            getattr(config, "PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4", ""))
        engagement = get_engagement(plan.engagement_id)
        if (engagement is None or engagement.sketch_state_schema != "provider-keyed-v2"
                or engagement.active_revision != plan.revision_id
                or _target_for_engagement(engagement).name != "barragan-testing"
                or evidence.get("target", {}).get("name") != "barragan-testing"):
            return False
        _require_configured_keyed_source()
        _verify_plan_evidence(plan)
        return True
    except Exception:
        return False


def _core_plan_public_detail(config: type, plan: Any) -> dict[str, Any]:
    detail = plan.to_dict()
    if plan.evidence.get("sketchStateSchema") == "provider-keyed-v2":
        detail["keyedDeployEligible"] = _keyed_core_plan_deploy_eligible(config, plan)
    return detail


@contextmanager
def _storage_context(app: FastAPI) -> Iterator[None]:
    with runtime_context(app.state.runtime):
        yield


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        value = await request.json()
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _database_status(app: FastAPI) -> dict[str, str]:
    uri = str(getattr(app.state.config, "SQLALCHEMY_DATABASE_URI", "") or "")
    parsed = urlparse(uri)
    seed_job = JobRunModel.query.filter_by(id="job-seed-001").first()
    return {
        "uriScheme": parsed.scheme or "unknown",
        "path": _safe_database_path(parsed),
        "seedStatus": "seeded" if seed_job is not None else "not_seeded",
    }


def _safe_database_path(parsed) -> str:
    if parsed.scheme != "sqlite":
        return "configured-external-database"
    if parsed.path == "/:memory:":
        return ":memory:"
    return str(Path(unquote(parsed.path)).resolve())


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _anonymous_session_payload(config: object) -> dict[str, Any]:
    return {
        "authRequired": bool(getattr(config, "AUTH_REQUIRED", False)),
        "authenticated": False,
        "user": None,
        "mustChangePassword": False,
    }


def _auth_session_payload(identity, csrf_token: str = "") -> dict[str, Any]:
    payload = {
        "authRequired": True,
        "authenticated": True,
        "user": {
            "id": identity.team_member_id,
            "username": identity.username,
            "displayName": identity.display_name,
            "roles": list(identity.roles),
        },
        "mustChangePassword": bool(identity.must_change_password),
        "absoluteExpiresAt": identity.absolute_expires_at.isoformat(),
        "idleExpiresAt": identity.idle_expires_at.isoformat(),
    }
    if csrf_token:
        payload["csrfToken"] = csrf_token
    return payload


def _set_session_cookie(response: JSONResponse, config: object, session_token: str) -> None:
    response.set_cookie(
        key=str(getattr(config, "AUTH_SESSION_COOKIE_NAME")),
        value=session_token,
        max_age=int(getattr(config, "AUTH_SESSION_ABSOLUTE_SECONDS", 12 * 60 * 60)),
        path="/",
        secure=bool(getattr(config, "AUTH_COOKIE_SECURE", False)),
        httponly=True,
        samesite="strict",
    )


def _clear_session_cookie(response: JSONResponse, config: object) -> None:
    response.delete_cookie(
        key=str(getattr(config, "AUTH_SESSION_COOKIE_NAME")),
        path="/",
        secure=bool(getattr(config, "AUTH_COOKIE_SECURE", False)),
        httponly=True,
        samesite="strict",
    )


async def _certificate_lifecycle_response(app: FastAPI, operation, engagement_id: str, certificate_id: str, request: Request) -> Any:
    body = await _json_body(request)
    with _storage_context(app):
        try:
            result = operation(
                engagement_id,
                certificate_id,
                body,
                requested_by=str(body.get("requestedBy") or "operator"),
            )
        except CertificateManagerValidationError as exc:
            return JSONResponse({"errors": exc.errors}, status_code=400)
        if result is None:
            raise HTTPException(status_code=404, detail="certificate not found")
        return JSONResponse(result, status_code=202)


async def _inbound_channel_certificate_lifecycle_response(app: FastAPI, operation, engagement_id: str, channel_id: str, request: Request) -> Any:
    body = await _json_body(request)
    with _storage_context(app):
        try:
            result = operation(
                engagement_id,
                channel_id,
                body,
                requested_by=str(body.get("requestedBy") or "operator"),
            )
        except InboundChannelCertificateValidationError as exc:
            return JSONResponse({"errors": exc.errors}, status_code=400)
        if result is None:
            raise HTTPException(status_code=404, detail="engagement not found")
        return JSONResponse(result, status_code=202)


def _operational_mutation_engagement_id(method: str, path: str) -> str:
    if method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return ""
    parts = [part for part in path.split("/") if part]
    if len(parts) < 4 or parts[:2] != ["api", "engagements"]:
        return ""
    operational_roots = {
        "sketch-chains",
        "outbound-channels",
        "inbound-channels",
        "inspector-settings",
        "observer-settings",
        "observer-checks",
        "inspections",
    }
    return parts[2] if parts[3] in operational_roots else ""


def _core_host_mutation_engagement_id(method: str, path: str) -> str:
    if method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
        return ""
    parts = [part for part in path.split("/") if part]
    if len(parts) < 4 or parts[:2] != ["api", "engagements"]:
        return ""
    # The aggregate endpoint performs its own persisted-state single-flight
    # check so a retrying browser receives the active parent summary instead
    # of a generic middleware conflict.
    if len(parts) == 5 and parts[3:] == ["capabilities", "apply"]:
        return ""
    core_host_roots = {
        "deployment-plans",
        "infrastructure",
        "team",
        "capabilities",
        "services",
        "outbound-channels",
        "inbound-channels",
    }
    return parts[2] if parts[3] in core_host_roots else ""


app = create_app()
