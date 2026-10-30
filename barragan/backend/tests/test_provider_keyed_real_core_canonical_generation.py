# Copyright (c) 2026, Oracle and/or its affiliates.
"""A real persisted keyed core plan, stopping before OCI apply.

The engagement, revision, durable workspace, and core plan use their production
writers. Only Terraform CLI output is supplied by this disposable test.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
from uuid import uuid4

import pytest

from app.services import core_deployment_plans as core_plans
from app.domain import JobEvent
from app.integrations import oci_read_validation, pilot_standard_rti
from app.integrations.linode_validation import LinodeValidationError
from app.integrations.command_resolution import CommandResolution
from app.integrations.managed_host_images import MANAGED_HOST_IMAGE_PROFILES
from app.services import observer_checks
from app.services import provider_keyed_inspector_preparation_proof as inspector_ssh_proof
from app.services import provider_keyed_saved_plan_runner as sketch_terraform_runner
from app.services.provider_keyed_initial_attachment_adapter import (
    derive_digitalocean_initial_attachment_intent,
)
from app.services.provider_keyed_digitalocean_attachment import (
    reconcile_digitalocean_initial_attachment,
)
from app.services.provider_keyed_initial_host_publication import publish_initial_digitalocean_host_proof
from test_provider_keyed_initial_host_publication import _verify_fake as verify_external_host_fixture
from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_published_teardown_source import audit_published_provider_keyed_source
from app.services import provider_keyed_core_source as keyed_source
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_host_binding import bind_initial_digitalocean_host_identity
from app.services.provider_keyed_initial_bootstrap import bootstrap_initial_digitalocean_chains
from app.services.sketch_bootstrap_apply import BOOTSTRAP_COMMAND_TIMEOUT_SECONDS
from app.services.provider_keyed_initial_continuation import (
    _job_ids, start_fresh_digitalocean_initial_continuation,
)
from app.services.provider_keyed_initial_plan_job import _expected_inventory, _local_file
from app.services.provider_keyed_postapply_preflight import (
    preflight_applied_digitalocean_provider,
    read_applied_digitalocean_provider_for_teardown,
)
from app.services.provider_keyed_runtime_preflight import (
    _db_lease_lookup, preflight_fresh_digitalocean_provider,
)
from app.services.provider_keyed_teardown_quiescence import (
    audit_terminal_provider_keyed_bootstrap,
)
from app.services.provider_keyed_teardown_scope import build_digitalocean_keyed_teardown_scope
from app.services.provider_keyed_teardown_source import (
    ProviderKeyedTeardownSourceError, load_keyed_teardown_source,
)
from app.services.sketch_ssh_keys import ensure_sketch_ssh_key, retrieve_sketch_ssh_key
from app.services.provider_keyed_host_binding import _core_known_hosts
from app.services.core_deployment_plans import (
    CoreDeploymentPlanError, KEYED_CORE_TERRAFORM_INPUT_FILES,
    _begin_private_devtest_keyed_core_plan_apply, _verify_plan_evidence,
    get_core_deployment_plan, recover_interrupted_core_deployment_plans,
    require_keyed_core_terraform_source_manifest,
    start_core_deployment_plan,
)
from app.services.credentials import encrypt_secret_value, test_master_key as fixture_master_key
from app.services.engagement_teardown import (
    ENGAGEMENT_TEARDOWN_ACTION, _current_scope_snapshot, _parent_id,
    preview_engagement_teardown, start_engagement_teardown,
)
from app.services.engagement_workspaces import prepare_engagement_workspace
from app.services.provider_keyed_comprehensive_teardown import (
    _boundary, prove_retained_keyed_inspector_ready,
    recognize_retained_keyed_inspector_ready, run_provider_keyed_comprehensive_handoff,
    run_provider_keyed_destroy_preview_from_ready,
    publish_provider_keyed_destroy_absence, recognize_provider_keyed_destroy_absence,
    retire_provider_keyed_group_after_absence, recognize_provider_keyed_group_retired,
)
from app.services.provider_keyed_initial_destroy_plan_job import (
    run_digitalocean_initial_destroy_plan_job,
)
from app.services.provider_keyed_initial_destroy_apply_job import (
    preflight_digitalocean_initial_destroy_apply,
    run_digitalocean_initial_destroy_apply_job,
)
from app.services.provider_keyed_destroy_apply_continuation import (
    continue_digitalocean_keyed_destroy_apply,
    prove_live_keyed_inspector_before_destroy_go,
)
from app.services.provider_keyed_destroy_absence_preflight import (
    ProviderKeyedDestroyAbsencePreflightError,
    reconcile_successful_digitalocean_destroy_absence,
)
from app.services.provider_keyed_pending_retirement import (
    retire_pending_keyed_group_after_absence, recognize_pending_keyed_group_retired,
)
from app.services import provider_keyed_core_destroy_preview as core_destroy_preview
from app.services import provider_keyed_core_destroy_apply as core_destroy_apply
from app.services import provider_keyed_core_destroy_absence as core_destroy_absence
from app.services import provider_keyed_inspector_negative as inspector_negative
from app.services import provider_keyed_selector_retirement as selector_retirement
from app.services import provider_keyed_inspector_linode_cleanup as linode_cleanup
from app.services import provider_keyed_pending_dispatch as pending_dispatch
from app.services.provider_keyed_oci_core_state import parse_applied_oci_core_state
from app.services.provider_keyed_oci_exact_absence import prove_oci_core_visibility
from app.services.provider_keyed_inspector_negative import (
    prove_pending_keyed_inspector_negative,
)
from app.services.provider_keyed_inspector_preflight import inspect_prepared_keyed_teardown_inspector
from app.services.provider_region_policy import update_provider_region_policy
from app.services.redteam_infra_template import RedteamInfraTemplateSource, TEMPLATE_ROOT_ENV
from app.services.revisions import create_revision
from app.core.runtime import configure_runtime, runtime_context
from app.storage.credential_repository import SqlAlchemyCredentialRepository, StoredCredential
from app.storage.database import db
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository,
)
from app.storage.models import CoreMutationLeaseModel, DeploymentPlanModel
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_cleanup_visibility import Catalog as VisibilityCatalog, _pages as visibility_pages
from app.storage.engagement_repository import SqlAlchemyEngagementRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.domain_repository import SqlAlchemyDomainRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository
from redteam_infra_test_fixtures import checkout_local_pinned_source
from test_catalog_service import valid_standard_rti_payload
from test_core_deployment_plans import _planned_core_instances
from test_provider_keyed_persisted_intent import _inputs
from test_provider_keyed_oci_core_state import _state as _oci_state
from test_provider_keyed_oci_core_state import _ROLES as _OCI_ROLES
from test_provider_keyed_canonical_pending_generation import (
    _AbsentCatalog, _AttachmentCatalog, _EmptySelectorCatalog, _SelectorPost, _applied_state,
    _destroy_shown_plan, _gated_terraform, _shown_plan,
)
from test_provider_keyed_canonical_published_generation import _exact_oci_destroy_show


def _upstream_checkout() -> Path:
    source = Path(os.environ.get(
        "BARRAGAN_TEST_REDTEAM_INFRA",
        str(Path(__file__).resolve().parents[3] / "redteam-infra"),
    )).resolve()
    if not (source / ".git").exists():
        pytest.skip("real Redteam-infra checkout required")
    return source


def _keyed_parameters(chains):
    parameters = valid_standard_rti_payload()
    parameters["engagementName"] = "m4t8q2z7"
    parameters["sketchChains"] = [{
        "id": row.chain_id, "assignedProxy": row.assigned_proxy,
        "middleProvider": row.middle_provider, "middleRegion": row.middle_region,
        "middleSize": row.middle_size, "edgeProvider": row.edge_provider,
        "edgeRegion": row.edge_region, "edgeSize": row.edge_size,
        "edges": row.edge_intents,
    } for row in chains]
    parameters["egressProfiles"] = [{
        "name": f"egress-{index}", "sketchChainId": row.chain_id,
        "listenerPort": 3332 + index,
    } for index, row in enumerate(chains, 1)]
    parameters["ingressRoutes"] = [{
        "name": "test-ingress", "sketchChainId": chains[0].chain_id,
        "domain": "example.invalid",
    }]
    return parameters


@pytest.mark.parametrize("apply_case", [
    "bound", "crash", "stale_review", "prebind_error", "worker_tamper", "worker_success",
    pytest.param("worker_success_initial", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("worker_success_initial_host_response_lost", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("worker_success_initial_dispatch_absence", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("worker_success_initial_dispatch_core_apply", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("worker_success_initial_published_fixture", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("worker_success_initial_published_apply_drift", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("worker_success_initial_published_selector_ambiguous", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("visibility_denied", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    pytest.param("visibility_credential_changed", marks=pytest.mark.skipif(
        sys.platform != "linux", reason="reviewed Terraform release is Linux-only")),
    "region_unavailable",
])
def test_real_keyed_core_plan_is_persisted_and_reviewed_after_restart(
    tmp_path, monkeypatch, apply_case, published_cleanup_hook=None,
):
    upstream = _upstream_checkout()
    pinned = tmp_path / "pinned-redteam-infra"
    checkout_local_pinned_source(upstream, pinned, keyed_source._SOURCE_REVISION)
    monkeypatch.setenv(TEMPLATE_ROOT_ENV, str(pinned))
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", fixture_master_key())
    engagement, chains, _core, _plan, _profile = _inputs()
    engagement = replace(engagement, status="planned", active_revision="",
                         template_id="standard-rti",
                         input_parameters={**_keyed_parameters(chains),
                                           "deploymentTarget": engagement.input_parameters["deploymentTarget"]})
    state = db.configure(f"sqlite:///{tmp_path / 'real-core-plan.sqlite'}")
    runtime_settings = {
        "ENVIRONMENT": "devtest", "PROVIDER_KEYED_TEMPLATE_ROOT": str(pinned),
        "DATA_DIR": str(tmp_path / "data"),
    }
    published_case = apply_case in {
        "worker_success_initial_published_fixture",
        "worker_success_initial_published_apply_drift",
        "worker_success_initial_published_selector_ambiguous",
    }
    if published_case:
        runtime_settings["PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED"] = True
    runtime = configure_runtime(runtime_settings, state)
    workspace_root = tmp_path / "engagements"
    state_root = tmp_path / "terraform-state"
    key_path = tmp_path / "core-key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
                   check=True, capture_output=True)
    monkeypatch.setenv("BARRAGAN_VALIDATION_SSH_PRIVATE_KEY", str(key_path))
    monkeypatch.setenv("BARRAGAN_VALIDATION_SSH_PUBLIC_KEY", str(key_path.with_suffix(".pub")))
    with runtime_context(runtime), db.bind(state):
        db.create_all()
        update_provider_region_policy("digitalocean", {"allowedRegions": ["sfo3", "nyc3"]})
        SqlAlchemyEngagementRepository().save(engagement)
        for chain in chains:
            SqlAlchemySketchChainRepository().save(chain)
        SqlAlchemyCredentialRepository().save(StoredCredential(
            id="credential-opaque", provider="digitalocean", alias="team", status="active",
            description="", encrypted_secret=encrypt_secret_value("fixture-token"),
            is_default=True, created_at="2026-10-07T00:00:00+00:00",
            updated_at="2026-10-07T00:00:00+00:00",
        ))
        SqlAlchemyCredentialRepository().save(StoredCredential(
            id="linode-credential-opaque", provider="linode", alias="linode-team", status="active",
            description="", encrypted_secret=encrypt_secret_value("fixture-linode-token"),
            is_default=True, created_at="2026-10-07T00:00:00+00:00",
            updated_at="2026-10-07T00:00:00+00:00",
        ))
        revision = create_revision(engagement.id)
        prepared = prepare_engagement_workspace(
            engagement.id, root=workspace_root,
            source=RedteamInfraTemplateSource(pinned, "test"),
        )
        assert prepared is not None and prepared.created

        calls = []
        core_ips = {"homebase": "45.79.201.30", "proxy01": "45.79.201.31",
                    "proxy02": "45.79.201.32"}
        state_body = _oci_state(proxy_count=2, elk_enabled=False)
        state_values = {}
        for row in state_body["resources"]:
            attrs = row["instances"][0]["attributes"]
            if row["mode"] == "managed":
                attrs["freeform_tags"]["barragan_engagement"] = engagement.name
                if row["type"] != "oci_core_default_dhcp_options":
                    attrs["compartment_id"] = engagement.input_parameters["deploymentTarget"]["compartmentId"]
                if row["type"] == "oci_core_instance":
                    attrs["public_ip"] = core_ips[row["name"]]
            state_values[f'{row["type"]}.{row["name"]}'] = attrs
        state_body["outputs"] = {"public_ips": {"value": core_ips}}
        shown = _planned_core_instances(proxy_count=2, elk_enabled=False)
        planned = shown["planned_values"]["root_module"]["resources"]
        existing = {row["address"] for row in planned}
        for row in planned:
            row["mode"] = "managed"
            row["values"] = {**row["values"], **state_values[row["address"]]}
        for address, values in state_values.items():
            if address not in existing:
                resource_type, _ = address.split(".", 1)
                planned.append({
                    "address": address, "type": resource_type,
                    "mode": "data" if address.startswith(("oci_identity_", "oci_core_images."))
                    else "managed", "values": values,
                })
        assert {row["address"] for row in planned if row["mode"] == "managed"} == {
            f'{row["type"]}.{row["name"]}' for row in state_body["resources"]
            if row["mode"] == "managed"
        }
        assert all(all(row["values"].get(key) == value for key, value in state_values[row["address"]].items())
                   for row in planned)
        shown["resource_changes"] = [{
            "address": row["address"], "type": row["type"],
            "provider_name": "registry.terraform.io/oracle/oci",
            "change": {"actions": ["read" if row["mode"] == "data" else "create"],
                       "before": None, "after": row["values"]},
        } for row in planned]
        shown["output_changes"] = {"public_ips": {
            "actions": ["create"], "before": None, "after": core_ips,
        }}

        def terraform(args, cwd, env):
            calls.append(tuple(args))
            assert Path(cwd).is_dir() and env["TF_DATA_DIR"]
            operation = args[1]
            if operation == "init":
                (Path(cwd) / ".terraform.lock.hcl").write_text("# disposable pinned lock fixture\n")
                return subprocess.CompletedProcess(args, 0, "", "")
            if operation == "plan":
                out_path = Path(next(value[5:] for value in args if value.startswith("-out=")))
                out_path.write_bytes(b"opaque reviewed OCI plan fixture")
                return subprocess.CompletedProcess(args, 2, "", "")
            if operation == "show" and "-json" in args:
                return subprocess.CompletedProcess(args, 0, json.dumps(shown), "")
            if operation == "show":
                return subprocess.CompletedProcess(args, 0, "Plan: 12 to add, 0 to change, 0 to destroy.", "")
            if operation == "version":
                return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
            pytest.fail("unexpected Terraform operation")

        monkeypatch.setattr(core_plans, "resolve_terraform",
                            lambda: SimpleNamespace(command="/usr/bin/terraform"))
        monkeypatch.setattr(core_plans, "_run_command", terraform)
        plan = start_core_deployment_plan(
            engagement.id, {"revisionId": revision["id"], "sshSourceCidrs": ["8.8.8.8/32"]},
            background_runner=lambda task: task(), command_runner=terraform,
            engagement_workspace_root=workspace_root, terraform_state_root=state_root,
        )
        assert plan.status == "ready", plan.error
        assert [args[1] for args in calls] == ["init", "plan", "show", "show", "version"]
        assert plan.review["counts"] == {
            "add": 12, "update": 0, "replace": 0, "remove": 0, "read": 2, "output": 1,
        }
        assert plan.review["sketchStateSchema"] == "provider-keyed-v2"
        assert plan.evidence["sketchStateSchema"] == "provider-keyed-v2"
        assert plan.evidence["pendingSketchChainIds"] == [row.chain_id for row in chains]
        assert Path(plan.evidence["runDirectory"]).is_dir()
        assert Path(plan.evidence["planPath"]).is_file()
        assert not Path(plan.evidence["terraformStatePath"]).exists()
        assert prepared.workspace.template_source["git"]["isCheckout"] is True
        assert set(plan.evidence["keyedCoreTerraformSourceManifest"]["sha256"]) == set(
            KEYED_CORE_TERRAFORM_INPUT_FILES,
        )
        assert plan.evidence["planFingerprint"] == hashlib.sha256(
            Path(plan.evidence["planPath"]).read_bytes(),
        ).hexdigest()
        require_keyed_core_terraform_source_manifest(
            Path(plan.evidence["runDirectory"]), plan.evidence["keyedCoreTerraformSourceManifest"],
        )
        assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []

    class SelectedVisibilityCatalog(VisibilityCatalog):
        def request(self, origin, method, path, token):
            assert token == "fixture-token"  # The selected encrypted SQLite credential.
            return super().request(origin, method, path, "token-fixture")

    visibility_catalog = SelectedVisibilityCatalog(visibility_pages())

    def selected_regions(origin, method, path, token):
        assert (origin, method, path, token) == (
            "https://api.digitalocean.com/v2", "GET", "/regions?per_page=200",
            "fixture-token")
        return {"regions": [
            {"slug": "nyc3", "available": True, "sizes": ["s-1vcpu-1gb"]},
            {"slug": "sfo3", "available": True,
             "sizes": [] if apply_case == "region_unavailable" else ["s-1vcpu-1gb"]},
        ], "links": {}, "meta": {"total": 2}}

    def private_keyed_apply(engagement_id, plan_id, **options):
        return _begin_private_devtest_keyed_core_plan_apply(
            engagement_id, plan_id, cleanup_visibility_transport=visibility_catalog,
            region_catalog_transport=SimpleNamespace(request=selected_regions),
            **options,
        )

    reopened = db.configure(state.uri)
    with runtime_context(configure_runtime(runtime_settings, reopened)), db.bind(reopened):
        saved = SqlAlchemyDeploymentPlanRepository().get(plan.id)
        assert saved == plan
        assert get_core_deployment_plan(engagement.id, plan.id) == saved
        _verify_plan_evidence(saved)
        assert SqlAlchemyEngagementRepository().get(engagement.id).active_revision == revision["id"]
        assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
        assert not Path(saved.evidence["terraformStatePath"]).exists()
        assert len([args for args in calls if args[1] == "plan"]) == 1

        source = Path(saved.evidence["runDirectory"]) / KEYED_CORE_TERRAFORM_INPUT_FILES[0]
        original = source.read_bytes()
        source.write_bytes(original + b"\n# tampered source\n")
        with pytest.raises(CoreDeploymentPlanError):
            _verify_plan_evidence(saved)
        with pytest.raises(CoreDeploymentPlanError):
            private_keyed_apply(
                engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker ran"),
            )
        assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
        assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
        source.write_bytes(original)
        _verify_plan_evidence(saved)
        assert SqlAlchemyDeploymentPlanRepository().get(plan.id) == saved
        assert len([args for args in calls if args[1] == "plan"]) == 1

        if apply_case in {"visibility_denied", "visibility_credential_changed"}:
            if apply_case == "visibility_denied":
                visibility_catalog.pages["/images?page=1&per_page=200&private=true"] = (
                    PermissionError("403: image:read unavailable")
                )
            else:
                credentials = SqlAlchemyCredentialRepository()
                selected = credentials.get(plan.evidence["sketchAuthorization"]["providerConnectionId"])
                credentials.save(replace(
                    selected, encrypted_secret=encrypt_secret_value("different-token"),
                ))
                assert credentials.get(selected.id).encrypted_secret != selected.encrypted_secret
            with pytest.raises(CoreDeploymentPlanError):
                private_keyed_apply(
                    engagement.id, plan.id,
                    background_runner=lambda task: pytest.fail("core worker launched"),
                )
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == (
                "ready" if apply_case == "visibility_denied" else "invalidated"
            )
            assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
            assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
            assert not any(path.startswith("/databases") for path in visibility_catalog.calls)
            if apply_case == "visibility_denied":
                assert visibility_catalog.calls == [
                    "/droplets?page=1&per_page=200",
                    "/droplets?page=1&per_page=200&type=gpus",
                    "/images?page=1&per_page=200&private=true",
                ]
            else:
                assert visibility_catalog.calls == []
            assert not any(args[1] == "apply" for args in calls)
            return

        if apply_case == "region_unavailable":
            with pytest.raises(CoreDeploymentPlanError, match="core deployment plan validation failed") as exc:
                private_keyed_apply(
                    engagement.id, plan.id,
                    background_runner=lambda task: pytest.fail("core worker launched"),
                )
            assert "size s-1vcpu-1gb is unavailable in region sfo3" in exc.value.errors[0]
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == "ready"
            assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
            assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
            assert not any(args[1] == "apply" for args in calls)
            return

        if apply_case == "stale_review":
            original_begin = SqlAlchemyDeploymentPlanRepository.begin_private_keyed_core_apply

            def interpose_plan_change(repo, reviewed):
                # Simulate a second operator changing the reviewed plan after
                # source verification but before this reservation obtains GO.
                DeploymentPlanModel.query.filter_by(id=reviewed.id).update(
                    {"status": "reconciliation_required"}, synchronize_session=False,
                )
                db.session.commit()
                return original_begin(repo, reviewed)

            monkeypatch.setattr(SqlAlchemyDeploymentPlanRepository,
                                "begin_private_keyed_core_apply", interpose_plan_change)
            with pytest.raises(DeploymentPlanConflictError):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker ran"),
                )
            assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
            assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
        elif apply_case == "prebind_error":
            from app.services import guarded_test_deployment

            def fail_before_binding(*args, **kwargs):
                assert CoreMutationLeaseModel.query.filter_by(
                    engagement_id=engagement.id, owner_id=plan.id, operation="apply",
                ).count() == 1
                raise RuntimeError("injected pre-bind failure")

            monkeypatch.setattr(guarded_test_deployment, "start_guarded_pilot_standard_rti_run",
                                fail_before_binding)
            with pytest.raises(RuntimeError, match="injected pre-bind failure"):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker ran"),
                )
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == "ready"
            assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
            assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
        elif apply_case == "crash":
            reserved = SqlAlchemyDeploymentPlanRepository().begin_private_keyed_core_apply(saved)
            assert reserved.status == "applying" and reserved.apply_job_id == ""
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id, operation="apply",
            ).count() == 1
            with pytest.raises(CoreDeploymentPlanError):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker replayed"),
                )
        elif apply_case in {"bound", "worker_tamper", "worker_success", "worker_success_initial",
                            "worker_success_initial_host_response_lost",
                            "worker_success_initial_dispatch_absence",
                            "worker_success_initial_dispatch_core_apply",
                            "worker_success_initial_published_fixture",
                            "worker_success_initial_published_apply_drift",
                            "worker_success_initial_published_selector_ambiguous"}:
            deferred = []
            applying, job = private_keyed_apply(
                engagement.id, plan.id, background_runner=deferred.append,
            )
            assert applying.status == "applying" and applying.apply_job_id == job.id
            assert len(deferred) == 1
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id, operation="apply",
            ).count() == 1
            assert len(SqlAlchemyJobRepository().list_for_engagement(engagement.id)) == 1
            assert visibility_catalog.calls == [
                "/droplets?page=1&per_page=200",
                "/droplets?page=1&per_page=200&type=gpus",
                "/images?page=1&per_page=200&private=true",
                "/volumes?page=1&per_page=200",
                "/snapshots?page=1&per_page=200&resource_type=volume",
                "/firewalls?page=1&per_page=200",
            ]
        else:
            pytest.fail("unknown apply case")
        assert len([args for args in calls if args[1] == "plan"]) == 1
        assert not any(args[1] == "apply" for args in calls)

    reopened_again = db.configure(state.uri)
    with runtime_context(configure_runtime(runtime_settings, reopened_again)), db.bind(reopened_again):
        if apply_case == "crash":
            recover_interrupted_core_deployment_plans()
            recovered = SqlAlchemyDeploymentPlanRepository().get(plan.id)
            assert recovered.status == "reconciliation_required"
            assert recovered.apply_job_id == ""
            assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
            assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
            with pytest.raises(CoreDeploymentPlanError):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker replayed"),
                )
        elif apply_case == "bound":
            current = SqlAlchemyDeploymentPlanRepository().get(plan.id)
            assert current.status == "applying" and current.apply_job_id == job.id
            with pytest.raises((CoreDeploymentPlanError, DeploymentPlanConflictError)):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker replayed"),
                )
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id, operation="apply",
            ).count() == 1
            assert len(SqlAlchemyJobRepository().list_for_engagement(engagement.id)) == 1
            recover_interrupted_core_deployment_plans()
            recovered = SqlAlchemyDeploymentPlanRepository().get(plan.id)
            assert recovered.status == "reconciliation_required"
            assert recovered.apply_job_id == job.id
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id, operation="apply",
            ).count() == 1
            with pytest.raises(CoreDeploymentPlanError):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker replayed"),
                )
        elif apply_case == "worker_tamper":
            def binary(name):
                return CommandResolution(name, f"/usr/bin/{name}", "fixture", ())

            monkeypatch.setattr(pilot_standard_rti, "resolve_terraform", lambda **kwargs: binary("terraform"))
            monkeypatch.setattr(pilot_standard_rti, "resolve_oci_cli", lambda **kwargs: binary("oci"))
            monkeypatch.setattr(pilot_standard_rti, "resolve_ansible", lambda **kwargs: binary("ansible"))
            monkeypatch.setattr(pilot_standard_rti, "resolve_ansible_playbook",
                                lambda **kwargs: binary("ansible-playbook"))
            monkeypatch.setattr(oci_read_validation, "resolve_oci_cli", lambda **kwargs: binary("oci"))
            external = []

            def external_command(command, cwd):
                external.append(tuple(command))
                if command[0] == "/usr/bin/oci":
                    return subprocess.CompletedProcess(command, 0, '{"data": []}', "")
                pytest.fail("Terraform apply or host command ran after source tamper")

            monkeypatch.setattr(pilot_standard_rti, "_run_command", external_command)
            observed_commands = []

            def forbid_observed_command(command, cwd, command_class, emit_activity):
                observed_commands.append(tuple(command))
                raise AssertionError("observed Terraform or host command ran after source tamper")

            # _run_guarded_command chooses this Popen path when its runner is
            # the module-level _run_command, even when that name is patched.
            monkeypatch.setattr(pilot_standard_rti, "_run_observed_command", forbid_observed_command)
            source = Path(plan.evidence["runDirectory"]) / KEYED_CORE_TERRAFORM_INPUT_FILES[0]
            source.write_bytes(source.read_bytes() + b"\n# changed after apply reservation\n")
            result = deferred[0]()  # The production worker, with only external command I/O replaced.
            assert result.status == "failed"
            assert all(command[0] == "/usr/bin/oci" for command in external)
            assert external
            assert observed_commands == []
            failed_job = SqlAlchemyJobRepository().get(job.id)
            assert failed_job.status == "failed"
            assert failed_job.events[-1].data["errorType"] == "CoreDeploymentPlanError"
            assert any(event.message == "OCI read preflight completed"
                       and event.data.get("ok") is True for event in failed_job.events)
            assert not any(event.message == "applied OCI core state sealed" for event in failed_job.events)
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == "reconciliation_required"
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id, operation="apply",
            ).count() == 1
            with pytest.raises(CoreDeploymentPlanError):
                private_keyed_apply(
                    engagement.id, plan.id, background_runner=lambda task: pytest.fail("worker replayed"),
                )
        elif apply_case in {"worker_success", "worker_success_initial",
                              "worker_success_initial_host_response_lost",
                              "worker_success_initial_dispatch_absence",
                              "worker_success_initial_dispatch_core_apply",
                              "worker_success_initial_published_fixture",
                              "worker_success_initial_published_apply_drift",
                              "worker_success_initial_published_selector_ambiguous"}:
            from app.services import guarded_test_deployment
            from app.services.provider_keyed_inspector_prepare_binder import (
                _existing_key_identity, _safe_key_identity, _verify_key_pair,
            )
            from app.services.provider_keyed_inspector_submit import _existing_public_key

            inspector_key_dir = Path(runtime_settings["DATA_DIR"]) / "inspector-keys"
            inspector_key_dir.mkdir(parents=True, mode=0o700)
            inspector_key_path = inspector_key_dir / "id_ed25519"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(inspector_key_path)], check=True, capture_output=True)
            inspector_key_path.chmod(0o600)
            inspector_public = inspector_key_path.with_suffix(".pub").read_text().strip()
            derived_public = subprocess.run(
                ["ssh-keygen", "-y", "-f", str(inspector_key_path)],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            assert derived_public.split()[:2] == inspector_public.split()[:2]
            assert inspector_key_path != key_path
            inspector_private_bytes = inspector_key_path.read_bytes()
            inspector_public_bytes = inspector_key_path.with_suffix(".pub").read_bytes()
            inspector_fingerprint = hashlib.sha256(inspector_public_bytes.strip()).hexdigest()
            simulated_host_key_path = tmp_path / "simulated-core-host-key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(simulated_host_key_path)], check=True, capture_output=True)
            host_pin = " ".join(simulated_host_key_path.with_suffix(".pub").read_text().split()[:2])
            assert host_pin != " ".join(inspector_public.split()[:2])
            known_hosts_path = Path(plan.evidence["runDirectory"]) / "ssh" / "known_hosts"

            def binary(name):
                return CommandResolution(name, f"/usr/bin/{name}", "fixture", ())

            monkeypatch.setattr(pilot_standard_rti, "resolve_terraform", lambda **kwargs: binary("terraform"))
            monkeypatch.setattr(pilot_standard_rti, "resolve_oci_cli", lambda **kwargs: binary("oci"))
            monkeypatch.setattr(pilot_standard_rti, "resolve_ansible", lambda **kwargs: binary("ansible"))
            monkeypatch.setattr(pilot_standard_rti, "resolve_ansible_playbook",
                                lambda **kwargs: binary("ansible-playbook"))
            monkeypatch.setattr(oci_read_validation, "resolve_oci_cli", lambda **kwargs: binary("oci"))
            monkeypatch.setattr(observer_checks, "resolve_ansible_playbook",
                                lambda **kwargs: binary("ansible-playbook"))
            external = []
            observed_commands = []
            host_pin_writes = []
            inspector_host_commands = []
            provider_calls = []
            expected_apply = [
                "env", f'TF_DATA_DIR={plan.evidence["terraformDataDir"]}',
                "/usr/bin/terraform", "apply", "-input=false", "-auto-approve",
                f'-state={plan.evidence["terraformStatePath"]}', plan.evidence["planPath"],
            ]
            expected_output = [
                "env", f'TF_DATA_DIR={plan.evidence["terraformDataDir"]}',
                "/usr/bin/terraform", "output", "-json",
                f'-state={plan.evidence["terraformStatePath"]}',
            ]

            def external_read(command, cwd):
                external.append(tuple(command))
                if command[0] == "/usr/bin/oci":
                    return subprocess.CompletedProcess(command, 0, '{"data": []}', "")
                pytest.fail("unexpected external preflight command")

            def observed(command, cwd, command_class, emit_activity):
                external.append(tuple(command))
                observed_commands.append(tuple(command))
                assert cwd == Path(plan.evidence["runDirectory"])
                if command == expected_apply:
                    Path(plan.evidence["terraformStatePath"]).write_text(json.dumps(state_body))
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command == expected_output:
                    return subprocess.CompletedProcess(command, 0,
                        json.dumps({"public_ips": {"value": core_ips}}), "")
                if command[0] in {"/usr/bin/ansible", "/usr/bin/ansible-playbook"}:
                    if "ansible.builtin.wait_for_connection" in command:
                        assert command[0:2] == ["/usr/bin/ansible", "pilot_rti"]
                        assert command.count("ansible.builtin.wait_for_connection") == 1
                        assert any(f"UserKnownHostsFile={known_hosts_path}" in part
                                   for part in command)
                        assert not known_hosts_path.exists()
                        known_hosts_path.write_text("".join(
                            f"{address} {host_pin}\n" for address in core_ips.values()
                        ), encoding="utf-8")
                        known_hosts_path.chmod(0o600)
                        host_pin_writes.append(str(known_hosts_path))
                    return subprocess.CompletedProcess(command, 0, "", "")
                pytest.fail("unexpected observed infrastructure command")

            monkeypatch.setattr(pilot_standard_rti, "_run_command", external_read)
            monkeypatch.setattr(pilot_standard_rti, "_run_observed_command", observed)

            class LinodeTransport:
                def request(self, method, path, token, body=None):
                    provider_calls.append((method, path))
                    assert token == "fixture-linode-token"
                    if (method, path) == ("POST", "/networking/firewalls"):
                        return {"id": 67890}
                    if (method, path) == ("POST", "/linode/instances"):
                        assert body["firewall_id"] == 67890
                        assert body["image"] == MANAGED_HOST_IMAGE_PROFILES["ubuntu-24.04"].linode_image
                        assert body["authorized_keys"] == [inspector_public]
                        return {"id": 12345}
                    if (method, path) == ("GET", "/linode/instances/12345"):
                        return {"id": 12345, "status": "running", "ipv4": ["45.79.201.25"]}
                    pytest.fail("unexpected Inspector provider request")

            proof_fence_calls = []

            def external_host_result(command):
                inspector_host_commands.append(tuple(command))
                assert command[0] in {"ssh", "/usr/bin/ansible-playbook"}
                assert command[0] == "/usr/bin/ansible-playbook" or any(
                    "@45.79.201.25" in part for part in command
                )
                if "root@45.79.201.25" in command:
                    return subprocess.CompletedProcess(command, 255, "", "Permission denied (publickey)")
                if command[-2:] == ["/usr/bin/printenv", "SSH_CONNECTION"]:
                    return subprocess.CompletedProcess(
                        command, 0, "8.8.8.8 55444 45.79.201.25 22\n", "",
                    )
                if "-T" in command:
                    return subprocess.CompletedProcess(command, 0,
                        "permitrootlogin no\npasswordauthentication no\nkbdinteractiveauthentication no\n", "")
                if command[-2:] == ["/usr/bin/nmap", "--version"]:
                    return subprocess.CompletedProcess(command, 0, "Nmap version 7.94\n", "")
                return subprocess.CompletedProcess(command, 0, "", "")

            def host_run(command, *, cwd=None, check=True, fence=None, timeout_seconds=120):
                # Match _run_checked's pre/post fence semantics even though
                # the external SSH/Ansible subprocess is simulated.
                if fence is not None:
                    fence()
                    proof_fence_calls.append("before")
                try:
                    return external_host_result(command)
                finally:
                    if fence is not None:
                        fence()
                        proof_fence_calls.append("after")

            monkeypatch.setattr(observer_checks, "_run_checked", host_run)
            provider = observer_checks.LinodeObserverProvider(
                transport=LinodeTransport(), poll_attempts=1, poll_delay_seconds=0,
                management_source_resolver=lambda: "8.8.8.8/32",
                image=MANAGED_HOST_IMAGE_PROFILES["ubuntu-24.04"].linode_image,
            )
            real_readiness = observer_checks.ensure_continuous_inspector_ready

            def readiness(engagement_id, **kwargs):
                return real_readiness(
                    engagement_id, **kwargs, provider_factory=lambda selected: provider,
                    runner=observer_checks.SshObserverRunner(
                        readiness_attempts=1, readiness_delay_seconds=0,
                    ),
                )

            monkeypatch.setattr(guarded_test_deployment, "ensure_continuous_inspector_ready", readiness)
            original_popen = subprocess.Popen
            allowed_git = []

            def pinned_source_git_only(command, *args, **kwargs):
                if (isinstance(command, list) and (
                    command[:4] == ["git", "--no-optional-locks", "-C", str(pinned)]
                    and command[4] in {"rev-parse", "status", "show", "ls-files", "cat-file"}
                    or command[:3] == ["git", "-C", str(pinned)]
                    and command[3] in {"rev-parse", "status", "show", "ls-files", "cat-file"}
                )):
                    allowed_git.append(tuple(command))
                    return original_popen(command, *args, **kwargs)
                pytest.fail("unfenced external process")

            scheduled_initial_dispatch = []

            def defer_initial_dispatch(core_id, *, environment, rollout_enabled):
                scheduled_initial_dispatch.append((core_id, environment, rollout_enabled))

            try:
                monkeypatch.setattr(subprocess, "Popen", pinned_source_git_only)
                with monkeypatch.context() as dispatch_scope:
                    if published_case:
                        from app.services import provider_keyed_initial_dispatch
                        # Keep the actual core-success router/authorization. Its
                        # continuation executes below with explicit offline I/O.
                        dispatch_scope.setattr(provider_keyed_initial_dispatch,
                                               "_recover_one", defer_initial_dispatch)
                    result = deferred[0]()
            finally:
                monkeypatch.setattr(subprocess, "Popen", original_popen)
            assert allowed_git
            if published_case:
                assert scheduled_initial_dispatch == [(job.id, "devtest", True)]
                assert SqlAlchemyJobRepository().get(job.id).input[
                    "providerKeyedDispatchAuthorized"] is True
            else:
                assert scheduled_initial_dispatch == []
            assert result.status == "succeeded", [
                (event.message, event.data.get("errorType"))
                for event in SqlAlchemyJobRepository().get(job.id).events[-6:]
            ]
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == "applied"
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id,
                operation="provider_keyed_initial",
            ).count() == 1

            assert any(event.message == "applied OCI core state sealed"
                       for event in SqlAlchemyJobRepository().get(job.id).events)
            pinned_path, pinned_digest = _core_known_hosts(SqlAlchemyJobRepository().get(job.id))
            assert pinned_path == str(known_hosts_path)
            assert pinned_digest == hashlib.sha256(known_hosts_path.read_bytes()).hexdigest()
            assert {line.split()[0] for line in known_hosts_path.read_text().splitlines()} == set(core_ips.values())
            seal_event = next(event for event in SqlAlchemyJobRepository().get(job.id).events
                              if event.message == "applied OCI core state sealed")
            assert seal_event.data["rawStateSha256"] == hashlib.sha256(
                Path(plan.evidence["terraformStatePath"]).read_bytes(),
            ).hexdigest()
            assert len(observed_commands) == 6
            assert host_pin_writes == [str(known_hosts_path)]
            assert list(observed_commands[0]) == expected_apply
            assert list(observed_commands[1]) == expected_output
            assert all(command[0] in {"/usr/bin/ansible", "/usr/bin/ansible-playbook"}
                       for command in observed_commands[2:])
            assert provider_calls == [
                ("POST", "/networking/firewalls"), ("POST", "/linode/instances"),
                ("GET", "/linode/instances/12345"),
            ]
            assert inspector_host_commands
            assert any("-T" in command for command in inspector_host_commands)
            assert any("root@45.79.201.25" in command for command in inspector_host_commands)
            playbooks = [Path(command[-1]).name for command in inspector_host_commands
                         if command[0] == "/usr/bin/ansible-playbook"]
            assert playbooks == ["harden_inspector_ssh.yml", "prepare_inspector.yml"]
            assert sum(command[-3:] == ("sudo", "-n", "true")
                       for command in inspector_host_commands) == 2
            settings = SqlAlchemyObserverSettingsRepository().get(engagement.id)
            assert settings.current_host["resourceId"] == "12345"
            assert observer_checks._inspector_support_baseline_current(
                observer_checks._reusable_inspector_host(settings),
            )
            records = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id)
            assert {(row.resource_type, row.resource_id, row.status) for row in records} == {
                ("inspector_instance", "12345", "active"), ("inspector_firewall", "67890", "active"),
            }
            assert any(row.action == observer_checks.INSPECTOR_READINESS_ACTION
                       and row.status == "succeeded"
                       for row in SqlAlchemyJobRepository().list_for_engagement(engagement.id))
        else:
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == (
                "ready" if apply_case == "prebind_error" else "reconciliation_required"
            )
            assert CoreMutationLeaseModel.query.filter_by(engagement_id=engagement.id).count() == 0
            assert SqlAlchemyJobRepository().list_for_engagement(engagement.id) == []
        assert not any(args[1] == "apply" for args in calls)

    if apply_case in {"worker_success", "worker_success_initial",
                         "worker_success_initial_host_response_lost",
                         "worker_success_initial_dispatch_absence",
                         "worker_success_initial_dispatch_core_apply",
                         "worker_success_initial_published_fixture",
                         "worker_success_initial_published_apply_drift",
                         "worker_success_initial_published_selector_ambiguous"}:
        terminal = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, terminal)), db.bind(terminal):
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id).status == "applied"
            assert SqlAlchemyJobRepository().get(job.id).status == "succeeded"
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id,
                operation="provider_keyed_initial",
            ).count() == 1
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id).current_host["resourceId"] == "12345"
            assert len(SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id)) == 2
            assert _core_known_hosts(SqlAlchemyJobRepository().get(job.id)) == (
                str(known_hosts_path), hashlib.sha256(known_hosts_path.read_bytes()).hexdigest(),
            )
            assert _safe_key_identity(_existing_key_identity) == (
                str(inspector_key_path), inspector_fingerprint,
            )
            assert _existing_public_key() == (inspector_public, inspector_fingerprint)
            _verify_key_pair(str(inspector_key_path), inspector_fingerprint)
            assert inspector_key_path.read_bytes() == inspector_private_bytes
            assert inspector_key_path.with_suffix(".pub").read_bytes() == inspector_public_bytes

    if apply_case in {"worker_success_initial", "worker_success_initial_host_response_lost",
                      "worker_success_initial_dispatch_absence",
                      "worker_success_initial_dispatch_core_apply",
                      "worker_success_initial_published_fixture",
                      "worker_success_initial_published_apply_drift",
                      "worker_success_initial_published_selector_ambiguous"}:
        from app.services.provider_keyed_initial_apply_job import run_fresh_digitalocean_initial_apply_job

        sketch_state_root = tmp_path / "sketch-state"
        sketch_state_root.mkdir(mode=0o700)
        monkeypatch.setenv("BARRAGAN_SKETCH_STATE_ROOT", str(sketch_state_root))
        initial = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, initial)), db.bind(initial):
            jobs = SqlAlchemyJobRepository()
            plans = SqlAlchemyDeploymentPlanRepository()
            inspector_before = SqlAlchemyObserverSettingsRepository().get(engagement.id)
            records_before = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id)
            core_before = jobs.get(job.id)
            plan_before = plans.get(plan.id)
            intent = preflight_fresh_digitalocean_provider(
                engagement.id, job.id, lease_owner=plan.id,
                environment="devtest", state_root=sketch_state_root,
            )
            keys = SqlAlchemySketchSshKeyRepository()
            ensure_sketch_ssh_key(engagement.id, keys)
            material = retrieve_sketch_ssh_key(engagement.id, keys)
            assert material is not None and material.public_key
            credential_id = SqlAlchemyCredentialRepository().get_default("digitalocean").id
            connection_digest = hashlib.sha256(
                f"digitalocean\0{credential_id}".encode(),
            ).hexdigest()
            workspace_path = (sketch_state_root / engagement.id / "provider-keyed-v2"
                              / "digitalocean" / connection_digest)
            material_dir = workspace_path.parents[1] / ".plan-material" / "digitalocean"
            private = material_dir / "admin-private"
            local_files = {
                "local_file.ansible_inventory[0]": _local_file(
                    "inventory.ini", _expected_inventory(intent, private)),
                "local_file.ssh_stanza[0]": _local_file(
                    str(material_dir / "ssh-output" / f"{intent.engagement_name}-sketch"), None),
            }
            shown = json.dumps(_shown_plan(intent, None, material.public_key, local_files))
            terraform_calls = []

            def terraform_command(args, cwd, env):
                assert args[0] == "/usr/bin/terraform" and cwd == workspace_path
                phase = args[1]
                terraform_calls.append(phase)
                if phase == "version":
                    return subprocess.CompletedProcess(args, 0, '{"terraform_version":"1.15.5"}', "")
                if phase == "plan":
                    plan_path = Path(next(arg.split("=", 1)[1] for arg in args
                                          if arg.startswith("-out=")))
                    plan_path.write_bytes(b"opaque reviewed binary plan fixture")
                if phase in {"init", "plan", "show"}:
                    return subprocess.CompletedProcess(args, 0,
                        shown if phase == "show" else "", "")
                pytest.fail("unexpected DigitalOcean Terraform command")

            monkeypatch.setattr(sketch_terraform_runner, "_run_command", terraform_command)
            selector_catalog = _EmptySelectorCatalog(intent.selector_tag)
            selector_post = _SelectorPost()
            gated, apply_calls = _gated_terraform(shown, _applied_state(intent))
            attachment_catalogs = []

            def apply_writer(child_id, **kwargs):
                return run_fresh_digitalocean_initial_apply_job(
                    child_id, **kwargs, selector_transport=selector_catalog,
                    selector_reservation_transport=selector_post,
                    catalog_transport=SimpleNamespace(request=selected_regions),
                    gated_command_runner=gated,
                )

            def attachment_reader(workspace, attachment_intent, **kwargs):
                catalog = _AttachmentCatalog(attachment_intent)
                attachment_catalogs.append(catalog)
                return reconcile_digitalocean_initial_attachment(
                    workspace, attachment_intent,
                    **{**kwargs, "max_attempts": 1, "poll_interval_seconds": 0},
                    transport=catalog,
                )

            parent = start_fresh_digitalocean_initial_continuation(
                job.id, environment="devtest", state_root=sketch_state_root,
                template_root=pinned, apply_runner=apply_writer,
                attachment_reconciler=attachment_reader,
            )
            assert parent.status == "running" and parent.input["phase"] == "awaiting_host_proof"
            assert parent.id == _job_ids(job.id)[0]
            assert jobs.get(_job_ids(job.id)[1]).status == "succeeded"
            assert jobs.get(_job_ids(job.id)[2]).status == "succeeded"
            assert terraform_calls == ["version", "init", "plan", "show"]
            assert apply_calls == ["show", "apply"]
            assert selector_post.calls == 1 and len(attachment_catalogs) == 1
            assert jobs.get(job.id) == core_before
            assert plans.get(plan.id) == plan_before
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before

        after_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, after_restart)), db.bind(after_restart):
            jobs = SqlAlchemyJobRepository()
            assert jobs.get(parent.id) == parent
            reviewed_intent, workspace, plan_evidence, applied = (
                read_applied_digitalocean_provider_for_teardown(
                    engagement.id, job.id, environment="devtest",
                    state_root=sketch_state_root, mode="applied_read",
                )
            )
            attachment_intent = derive_digitalocean_initial_attachment_intent(
                reviewed_intent, workspace, plan_evidence, applied,
            )
            assert attachment_intent.state_sha256 == parent.events[-1].data["stateSha256"]
            attachment = attachment_reader(
                workspace, attachment_intent, environment="devtest",
                deployment_target="barragan-testing",
                credential_repository=SqlAlchemyCredentialRepository(),
            )
            assert {node.droplet_id for node in attachment_intent.nodes} == set(
                parent.events[-1].data["verifiedDropletIds"])
            assert attachment is not None and len(attachment_catalogs) == 2
            assert start_fresh_digitalocean_initial_continuation(
                job.id, environment="devtest", state_root=sketch_state_root,
                template_root=pinned, apply_runner=apply_writer,
                attachment_reconciler=attachment_reader,
            ) == parent
            assert terraform_calls == ["version", "init", "plan", "show"]
            assert apply_calls == ["show", "apply"] and selector_post.calls == 1

            assert len(attachment_catalogs) == 2
            assert jobs.get(job.id) == core_before
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id) == plan_before
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert CoreMutationLeaseModel.query.filter_by(
                engagement_id=engagement.id, owner_id=plan.id,
                operation="provider_keyed_initial",
            ).count() == 1

            bound = bind_initial_digitalocean_host_identity(
                parent.id, environment="devtest", state_root=sketch_state_root,
                attachment_reconciler=attachment_reader,
            )
            assert bound.status == "running" and bound.input["phase"] == "host_identity_bound"
            manifest = next(event.data for event in bound.events
                            if event.message == "provider host identity binding intended")
            assert manifest["coreJobId"] == job.id and manifest["corePlanId"] == plan.id
            assert manifest["stateSha256"] == attachment_intent.state_sha256
            assert len(manifest["nodes"]) == len(intent.nodes)
            sketch_hosts = Path(manifest["sketchKnownHostsPath"])
            assert sketch_hosts.is_file() and sketch_hosts.read_bytes() == b""
            assert manifest["coreKnownHostsPath"] == str(known_hosts_path)

            host_commands = []
            pinned_chains = set()

            def host_process(command, *, scratch_path, intent_callback, started_callback,
                             heartbeat_callback, result_callback, provider_keyed_v2, env,
                             execution_timeout_seconds):
                assert execution_timeout_seconds == BOOTSTRAP_COMMAND_TIMEOUT_SECONDS
                assert provider_keyed_v2 is True and scratch_path.is_dir()
                assert command[0] == sys.executable
                phase = next((name for name, suffix in (
                    ("root_management_readiness", "wait_for_sketch_readiness.yml"),
                    ("upstream_root_bootstrap", "upstream-sketch-playbook.compat.yml"),
                    ("user_readiness", "wait_for_sketch_user_readiness.yml"),
                    ("transport_install", "install_sketch_transport.yml"),
                ) if any(str(part).endswith(suffix) for part in command)), None)
                assert phase is not None
                host_commands.append((scratch_path, phase))
                invocation = CommandIntent(
                    uuid4().hex, str(scratch_path),
                    hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
                )
                number = 2000 + len(host_commands)
                started = StartedCommand(invocation, ProcessIdentity(str(uuid4()), number, number, number))
                intent_callback(invocation)
                started_callback(started)
                heartbeat_callback(started)
                if phase == "root_management_readiness":
                    prepared = next(event.data for event in jobs.get(parent.id).events
                                    if event.message == "provider bootstrap preparation fenced")
                    chain_id = prepared["chainIds"][prepared["scratchPaths"].index(str(scratch_path))]
                    assert chain_id not in pinned_chains
                    with sketch_hosts.open("a", encoding="utf-8") as stream:
                        for node in manifest["nodes"]:
                            if node["chainId"] == chain_id:
                                stream.write(f"barragan-bootstrap-sketch-{node['name']} "
                                             f"ssh-ed25519 pinned-{node['name']}\n")
                    pinned_chains.add(chain_id)
                result_callback(CommandAuditResult(started, 0, 0, 0, False, False))
                return CommandResult(started, 0, "", "", False, False)

            bootstrapped = bootstrap_initial_digitalocean_chains(
                parent.id, environment="devtest", state_root=sketch_state_root,
                bootstrap_env={TEMPLATE_ROOT_ENV: str(pinned),
                               "ANSIBLE_PLAYBOOK_BIN": sys.executable},
                attachment_reconciler=attachment_reader,
                gated_command_runner=host_process,
            )
            assert bootstrapped.status == "running"
            assert bootstrapped.input["phase"] == "awaiting_strict_host_proof"
            assert [phase for _path, phase in host_commands] == [
                "root_management_readiness", "upstream_root_bootstrap",
                "user_readiness", "transport_install",
            ] * 2
            assert pinned_chains == set(bootstrapped.events[-1].data["chainIds"])
            assert len(sketch_hosts.read_text().splitlines()) == len(intent.nodes)
            assert terraform_calls == ["version", "init", "plan", "show"]
            assert apply_calls == ["show", "apply"] and selector_post.calls == 1
            assert jobs.get(job.id) == core_before
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id) == plan_before
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before

        bootstrap_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, bootstrap_restart)), db.bind(bootstrap_restart):
            assert SqlAlchemyJobRepository().get(parent.id) == bootstrapped
            scope = build_digitalocean_keyed_teardown_scope(
                engagement.id, job.id, environment="devtest", state_root=sketch_state_root,
            )
            evidence = audit_terminal_provider_keyed_bootstrap(
                job.id, confirmed_scope=scope, workspace_root=Path(scope["workspace"]),
            )
            assert evidence.parent_job_id == parent.id and evidence.command_count == 8
            assert len(evidence.scratch_paths) == 2
            assert terraform_calls == ["version", "init", "plan", "show"]
            assert apply_calls == ["show", "apply"] and selector_post.calls == 1

            if apply_case in {"worker_success_initial_published_fixture",
                              "worker_success_initial_published_apply_drift",
                              "worker_success_initial_published_selector_ambiguous"}:
                # This branch starts with the actual core plan/apply writer's
                # persisted state seal, then publishes the initial Sketch rows
                # before any teardown snapshot is reserved.
                reviewed = preflight_applied_digitalocean_provider(
                    engagement.id, job.id, lease_owner=plan.id,
                    environment="devtest", state_root=sketch_state_root,
                )
                attachment_intent = derive_digitalocean_initial_attachment_intent(*reviewed)
                attachment = attachment_reader(
                    reviewed[1], attachment_intent, environment="devtest",
                    deployment_target="barragan-testing",
                    credential_repository=SqlAlchemyCredentialRepository(),
                )
                chains_repo = SqlAlchemySketchChainRepository()
                pending = tuple(chains_repo.list_for_engagement(engagement.id))
                jobs = SqlAlchemyJobRepository()
                host_captures = []

                def collect_external_host(**options):
                    # External host observations are simulated; the real producer
                    # owns the child, fences, command journal and SQL publication.
                    node, spec = options["expected"], options["ssh_spec"]
                    assert spec.pinned_core_known_hosts_path == manifest["coreKnownHostsPath"]
                    assert spec.initial_sketch_known_hosts_path == manifest["sketchKnownHostsPath"]
                    assert options["manifest"] == manifest
                    assert spec.homebase.host == options["reviewed_core_route"]["homebasePublicIp"]
                    assert spec.proxy.host == options["reviewed_core_route"]["proxyPrivateIp"]
                    scratch = str(options["scratch_path"])
                    options["scratch_intent_callback"](SimpleNamespace(scratch_path=scratch))
                    for number in range(4):
                        invocation = CommandIntent(uuid4().hex, scratch, "a" * 64)
                        process_id = 6000 + 4 * len(host_captures) + number
                        started = StartedCommand(invocation, ProcessIdentity(
                            str(uuid4()), process_id, process_id, process_id))
                        options["intent_callback"](invocation)
                        options["started_callback"](started)
                        options["heartbeat_callback"](started)
                        options["result_callback"](CommandAuditResult(
                            started, 0, 1, 0, False, False))
                    host_captures.append(node.name)
                    return SimpleNamespace(name=node.name)

                finished = publish_initial_digitalocean_host_proof(
                    parent.id, environment="devtest", state_root=sketch_state_root,
                    attachment_reconciler=attachment_reader,
                    middle_collector=collect_external_host,
                    edge_collector=collect_external_host,
                    proof_verifier=verify_external_host_fixture,
                )
                assert finished.status == "succeeded"
                proof_child = jobs.get(
                    f"job-provider-keyed-initial-host-proof-{job.id.removeprefix('job-')}")
                assert proof_child.status == "succeeded"
                assert proof_child.events[-1].message == "strict host proof published"
                published = tuple(chains_repo.list_for_engagement(engagement.id))
                assert set(host_captures) == {
                    node["hostname"] for chain in published for node in chain.nodes}
                assert len(published) == 2
                assert all(row.status == "deployed" for row in published)
                assert jobs.get(parent.id).status == "succeeded"
                assert _db_lease_lookup(engagement.id) is None

                published_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, published_restart)), db.bind(published_restart):
                    source = audit_published_provider_keyed_source(
                        job.id, environment="devtest", state_root=sketch_state_root,
                    )
                    assert source.initial_job_id == parent.id
                    assert source.core_job_id == job.id
                    assert source.core_journal_sha256 == job_event_digest(
                        SqlAlchemyJobRepository().get(job.id).events)
                    assert source.chain_ids == tuple(scope["chainIds"])
                    assert source.chain_projection_sha256
                    sealed_core = [event for event in SqlAlchemyJobRepository().get(job.id).events
                                   if event.message == "applied OCI core state sealed"]
                    assert len(sealed_core) == 1
                    assert Path(plan.evidence["terraformStatePath"]).is_file()

                    sealed_cleanup_service_id = None
                    if published_cleanup_hook is not None:
                        sealed_cleanup_service_id = published_cleanup_hook(
                            jobs=SqlAlchemyJobRepository(), core=SqlAlchemyJobRepository().get(job.id),
                            initial=SqlAlchemyJobRepository().get(parent.id),
                            chains=SqlAlchemySketchChainRepository().list_for_engagement(engagement.id))
                    reviewed_preview = preview_engagement_teardown(job.id)
                    assert reviewed_preview is not None
                    jobs = SqlAlchemyJobRepository()
                    core = jobs.get(job.id)
                    snapshot = _current_scope_snapshot(
                        core, jobs=jobs, chains=SqlAlchemySketchChainRepository(),
                        resources=SqlAlchemyProviderResourceRepository(),
                        domain_repository=SqlAlchemyDomainRepository(),
                        inspector_state_reader=None, state_root=sketch_state_root,
                    )
                    assert snapshot["snapshotId"] == reviewed_preview["snapshotId"]
                    created = datetime.now(timezone.utc).isoformat()
                    proposal = StoredJobRun(
                        id=_parent_id(job.id), action=ENGAGEMENT_TEARDOWN_ACTION,
                        status="queued", target=f"engagement:{engagement.id}",
                        target_type="engagement", target_id=engagement.id,
                        requested_by=core.requested_by,
                        input={"engagementId": engagement.id, "coreJobId": job.id,
                               "scopeSnapshot": snapshot, "phase": "queued", "outcomes": {},
                               "remainingOwnedResources": [], "mutation": True,
                               "confirmation": "redacted"},
                        artifact_refs=[], created_at=created, started_at=None,
                        finished_at=None,
                        events=[JobEvent(1, "info", "engagement teardown queued",
                                         {"snapshotId": snapshot["snapshotId"]})],
                    )
                    if published_cleanup_hook is None:
                        teardown = jobs.reserve_published_keyed_teardown_parent(
                            proposal, reviewed_source=source, state_root=sketch_state_root,
                        )
                    else:
                        teardown = start_engagement_teardown(
                            job.id, {"confirmation": snapshot["confirmationPhrase"],
                                     "snapshotId": snapshot["snapshotId"]},
                            provider_keyed_environment="devtest",
                            provider_keyed_published_source=source,
                            provider_keyed_coordinator=lambda identifier: None,
                            provider_keyed_state_root=sketch_state_root,
                            job_repository=jobs,
                        )
                    assert teardown is not None
                    assert teardown.input["publishedSource"]
                    coordinator = run_provider_keyed_comprehensive_handoff(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                    )
                    assert coordinator.input["phase"] == "awaiting_inspector_preflight"
                    assert _db_lease_lookup(engagement.id) == (
                        plan.id, "provider_keyed_teardown_fence")

                    # The real read-only readiness writer seals the retained
                    # Inspector's selected credential, key and owned records.
                    selected_settings = SqlAlchemyObserverSettingsRepository().get(engagement.id)
                    selected_host = observer_checks._inspector_host_from_settings(
                        selected_settings.current_host, settings=selected_settings,
                    )
                    selected_firewall = selected_host.metadata["providerFirewall"]

                    class RetainedPublishedLinodeReads:
                        def request(self, method, path, token):
                            assert method == "GET" and token == "fixture-linode-token"
                            responses = {
                                "/linode/instances/12345": {
                                    "id": 12345, "label": selected_host.name,
                                    "region": selected_host.region, "type": selected_settings.size,
                                    "status": "running", "ipv4": [selected_host.public_ip],
                                    "tags": ["barragan", "inspector"],
                                },
                                "/networking/firewalls/67890": {
                                    "id": 67890, "label": selected_firewall["name"],
                                    "status": "enabled",
                                },
                                "/networking/firewalls/67890/rules": {
                                    "inbound_policy": "DROP", "outbound_policy": "ACCEPT",
                                    "inbound": [{"action": "ACCEPT", "protocol": "TCP",
                                                 "ports": "22", "addresses": {
                                                     "ipv4": ["8.8.8.8/32"]}}],
                                    "outbound": [],
                                },
                                "/networking/firewalls/67890/devices?page=1&page_size=100": {
                                    "data": [{"entity": {"type": "linode", "id": 12345}}],
                                    "page": 1, "pages": 1, "results": 1,
                                },
                            }
                            assert path in responses
                            return responses[path]

                    monkeypatch.setattr(inspector_ssh_proof, "_run_checked", host_run)
                    actual_subprocess_run = subprocess.run

                    def key_verification_only(command, *args, **kwargs):
                        assert command == ["/usr/bin/ssh-keygen", "-y", "-P", "", "-f",
                                           str(inspector_key_path)]
                        return actual_subprocess_run(command, *args, **kwargs)

                    monkeypatch.setattr(subprocess, "run", key_verification_only)
                    try:
                        retained_ready = prove_retained_keyed_inspector_ready(
                            teardown.id, environment="devtest", state_root=sketch_state_root,
                            management_source_resolver=lambda: "8.8.8.8/32",
                            transport=RetainedPublishedLinodeReads(),
                        )
                    finally:
                        monkeypatch.setattr(subprocess, "run", actual_subprocess_run)
                    assert retained_ready.coordinator_job_id == coordinator.id
                    ready = jobs.get(coordinator.id)
                    assert ready.input["phase"] == "inspector_ready"
                    assert ready.events[-1].message == "retained_inspector_ready"

                destroy_preview_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, destroy_preview_restart)), db.bind(destroy_preview_restart):
                    shown_destroy = _destroy_shown_plan(workspace_path)
                    destroy_preview_calls = []

                    def gated_destroy_preview(args, *, scratch_path, provider_keyed_v2,
                                              intent_callback, started_callback,
                                              heartbeat_callback, result_callback,
                                              **_kwargs):
                        phase = args[1]
                        assert args[0] == "/usr/bin/terraform"
                        assert phase in {"version", "init", "plan", "show"}
                        assert scratch_path == workspace_path and provider_keyed_v2 is True
                        destroy_preview_calls.append(phase)
                        invocation = CommandIntent(
                            str(uuid4()), str(scratch_path),
                            hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                        )
                        number = 3000 + len(destroy_preview_calls)
                        started = StartedCommand(invocation, ProcessIdentity(
                            str(uuid4()), number, number, number,
                        ))
                        intent_callback(invocation)
                        started_callback(started)
                        heartbeat_callback(started)
                        if phase == "plan":
                            output = Path(next(value[5:] for value in args
                                               if value.startswith("-out=")))
                            assert output.is_file()
                            output.write_bytes(b"opaque complete destroy plan fixture")
                        payload = (json.dumps({"terraform_version": "1.15.5"})
                                   if phase == "version" else shown_destroy
                                   if phase == "show" else "")
                        result_callback(CommandAuditResult(
                            started, 0, len(payload), 0, False, False))
                        return CommandResult(started, 0, payload, "", False, False)

                    def run_destroy_preview(parent_id, **options):
                        return run_digitalocean_initial_destroy_plan_job(
                            parent_id, **options,
                            gated_command_runner=gated_destroy_preview,
                        )

                    def read_destroy_preview(parent_id, **options):
                        return preflight_digitalocean_initial_destroy_apply(
                            parent_id, **options,
                            membership_transport=_AttachmentCatalog(attachment_intent),
                        )

                    destroy_preview = run_provider_keyed_destroy_preview_from_ready(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                        **({"retained_ready_recognizer": lambda *_a, **_kw: SimpleNamespace(
                            coordinator_job_id=ready.id)} if published_cleanup_hook is None else {}),
                        preview_runner=run_destroy_preview,
                        preview_recognizer=read_destroy_preview,
                    )
                    assert destroy_preview.status == "succeeded"
                    assert destroy_preview_calls == ["version", "init", "plan", "show"]

                destroy_apply_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, destroy_apply_restart)), db.bind(destroy_apply_restart):
                    destroy_apply_calls = []

                    def gated_destroy_apply(args, *, scratch_path, provider_keyed_v2,
                                            intent_callback, started_callback,
                                            heartbeat_callback, result_callback,
                                            **_kwargs):
                        phase = args[1]
                        assert args[0] == "/usr/bin/terraform"
                        assert phase in {"show", "apply"}
                        assert scratch_path == workspace_path and provider_keyed_v2 is True
                        destroy_apply_calls.append(phase)
                        invocation = CommandIntent(
                            str(uuid4()), str(scratch_path),
                            hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                        )
                        number = 4000 + len(destroy_apply_calls)
                        started = StartedCommand(invocation, ProcessIdentity(
                            str(uuid4()), number, number, number,
                        ))
                        intent_callback(invocation)
                        started_callback(started)
                        heartbeat_callback(started)
                        if phase == "apply":
                            state_path = workspace_path / "terraform.tfstate"
                            before = json.loads(state_path.read_text())
                            assert before["resources"]
                            state_path.write_text(json.dumps({
                                **before, "serial": before["serial"] + 1,
                                "resources": [],
                            }))
                            state_path.chmod(0o600)
                        payload = shown_destroy if phase == "show" else ""
                        result_callback(CommandAuditResult(
                            started, 0, len(payload), 0, False, False))
                        return CommandResult(started, 0, payload, "", False, False)

                    destroyed = run_digitalocean_initial_destroy_apply_job(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                        membership_transport=_AttachmentCatalog(attachment_intent),
                        live_inspector_prover=lambda *_a, **_kw: None,
                        gated_command_runner=gated_destroy_apply,
                        command_environment={},
                    )
                    assert destroyed.status == "succeeded"
                    assert destroy_apply_calls == ["show", "apply"]
                    assert json.loads((workspace_path / "terraform.tfstate").read_text())[
                        "resources"] == []

                historical_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, historical_restart)), db.bind(historical_restart):
                    historical = load_keyed_teardown_source(
                        teardown.id, phase="post_destroy", environment="devtest",
                        state_root=sketch_state_root,
                    )
                    assert historical.variant == "published"
                    assert historical.initial_journal_sha256 == source.initial_journal_sha256
                    absent_catalog = _AbsentCatalog(scope["selectorTag"])

                    def prove_absence(parent_id, **options):
                        return reconcile_successful_digitalocean_destroy_absence(
                            parent_id, **options, transport=absent_catalog,
                            poll_interval_seconds=0,
                        )

                    observed_absence = prove_absence(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                        max_attempts=1,
                    )
                    owned_ids = {row["address"]: row["id"] for row in scope["resources"]}
                    assert observed_absence.verified_absent_droplet_ids == tuple(sorted(
                        value for address, value in owned_ids.items()
                        if address.startswith("digitalocean_droplet.")
                    ))
                    assert observed_absence.verified_absent_firewall_id == owned_ids[
                        "digitalocean_firewall.firewall"]
                    assert observed_absence.verified_absent_ssh_key_id == owned_ids[
                        "digitalocean_ssh_key.key"]
                    assert len(absent_catalog.paths) == 5
                    provider_absent = publish_provider_keyed_destroy_absence(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                        **({"retained_ready_recognizer": lambda *_a, **_kw: SimpleNamespace(
                            coordinator_job_id=ready.id)} if published_cleanup_hook is None else {}),
                        absence_preflight=prove_absence,
                    )
                    assert provider_absent.input["phase"] == "provider_absent"
                    assert provider_absent.events[-1].message == "provider_absent"
                    assert len(absent_catalog.paths) == 15

                retirement_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, retirement_restart)), db.bind(retirement_restart):
                    assert recognize_provider_keyed_destroy_absence(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                    ) == provider_absent
                    retirement_catalog = _AbsentCatalog(scope["selectorTag"])

                    def prove_fresh_absence(parent_id, **options):
                        return reconcile_successful_digitalocean_destroy_absence(
                            parent_id, **options, transport=retirement_catalog,
                            poll_interval_seconds=0,
                        )

                    retired_rows = retire_provider_keyed_group_after_absence(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                        absence_preflight=prove_fresh_absence,
                    )
                    assert len(retired_rows) == 2
                    assert all(row.status == "destroyed" and row.nodes == []
                               for row in retired_rows)
                    assert len(retirement_catalog.paths) == 5
                    retired_coordinator = SqlAlchemyJobRepository().get(coordinator.id)
                    assert retired_coordinator.input["phase"] == "group_retired"
                    assert retired_coordinator.events[-1].data[
                        "priorChainProjectionSha256"] == source.chain_projection_sha256

                retired_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, retired_restart)), db.bind(retired_restart):
                    assert recognize_provider_keyed_group_retired(
                        teardown.id, environment="devtest", state_root=sketch_state_root,
                    ) == retired_rows

                oci_preview_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, oci_preview_restart)), db.bind(oci_preview_restart):
                    jobs = SqlAlchemyJobRepository()
                    selected_core = jobs.get(job.id)
                    core_plan = SqlAlchemyDeploymentPlanRepository().get(plan.id)
                    core_state_path = Path(core_plan.evidence["terraformStatePath"])
                    core_state_bytes = core_state_path.read_bytes()
                    core_inventory = parse_applied_oci_core_state(
                        core_state_bytes, proxy_count=core_plan.evidence["proxyCount"],
                        elk_enabled=core_plan.evidence["elkEnabled"],
                        compartment_id=core_plan.evidence["target"]["compartmentId"],
                        engagement_name=selected_core.input["engagementName"],
                    )
                    shown_core = _exact_oci_destroy_show(core_state_bytes, core_inventory)
                    monkeypatch.setattr(core_destroy_preview,
                                        "DEFAULT_TERRAFORM_STATE_ROOT", state_root)
                    oci_preview_calls = []

                    def core_preview_command(args, cwd, env):
                        oci_preview_calls.append(args[1])
                        assert cwd == Path(core_plan.evidence["runDirectory"])
                        assert env["TF_DATA_DIR"] == core_plan.evidence["terraformDataDir"]
                        if args[1] == "plan":
                            output = Path(next(arg[5:] for arg in args
                                               if arg.startswith("-out=")))
                            assert output.is_file()
                            output.write_bytes(b"reviewed OCI destroy plan fixture")
                            return subprocess.CompletedProcess(args, 2, "", "")
                        assert args[1:3] == ["show", "-json"]
                        return subprocess.CompletedProcess(args, 0, shown_core, "")

                    preview_options = dict(
                        environment="devtest", state_root=sketch_state_root,
                        retired_recognizer=lambda *_a, **_kw: pytest.fail(
                            "pending recognizer substituted for published history"),
                        release_check=lambda **_kw: SimpleNamespace(
                            path=Path("/usr/bin/terraform"), sha256="a" * 64,
                            version=core_plan.evidence["terraformFingerprint"]),
                        command_runner=core_preview_command,
                    )
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed later event", {})]))
                    with pytest.raises(core_destroy_preview.KeyedCoreDestroyPreviewAttention):
                        core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                            teardown.id, **preview_options)
                    assert oci_preview_calls == []
                    jobs.save(original_initial)
                    core_destroy_plan = core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                        teardown.id, **preview_options)
                    assert core_destroy_plan.status == "succeeded"
                    assert core_destroy_plan.events[-1].message == "core destroy preview saved"
                    assert core_destroy_plan.events[-1].data[
                        "stateSha256"] == hashlib.sha256(core_state_bytes).hexdigest()
                    assert oci_preview_calls == ["plan", "show"]

                oci_preview_reopen = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, oci_preview_reopen)), db.bind(oci_preview_reopen):
                    assert SqlAlchemyJobRepository().get(core_destroy_plan.id) == core_destroy_plan
                    with pytest.raises(core_destroy_preview.KeyedCoreDestroyPreviewAttention):
                        core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                            teardown.id, **{**preview_options,
                                "command_runner": lambda *_a, **_kw: pytest.fail(
                                    "one-shot OCI preview replayed")})
                    assert oci_preview_calls == ["plan", "show"]

                oci_apply_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, oci_apply_restart)), db.bind(oci_apply_restart):
                    monkeypatch.setattr(core_destroy_apply, "DEFAULT_TERRAFORM_STATE_ROOT", state_root)
                    target = core_plan.evidence["target"]
                    identity = {
                        "id": "ocid1.instance.oc1..barraganapp",
                        "compartmentId": target["compartmentId"],
                        "canonicalRegionName": target["region"],
                    }
                    observed_oci = {}
                    for resource in core_inventory.resources:
                        kind, role = _OCI_ROLES[resource.address]
                        observed_oci[resource.ocid] = {
                            "id": resource.ocid, "compartment-id": target["compartmentId"],
                            "freeform-tags": {
                                "barragan": "true", "barragan_engagement": engagement.name,
                                "barragan_environment": "barragan-testing",
                                "barragan_provider": "oci", "barragan_role": role,
                            },
                            "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
                        }
                    cli = tmp_path / "simulated-oci-cli"
                    cli.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                    cli.chmod(0o700)
                    oci_calls = []

                    def oci_read_command(argv, env):
                        oci_calls.append(tuple(argv))
                        assert argv[:8] == (
                            str(cli), "--auth", "instance_principal", "--region",
                            target["region"], "--output", "json", "--no-retry",
                        )
                        assert env["HOME"] == "/nonexistent"
                        if argv[10] == "list":
                            kind = {
                                "dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
                                "nat-gateway": "natgateway", "route-table": "routetable",
                                "security-list": "securitylist",
                            }.get(argv[9], argv[9])
                            rows = [row for ocid, row in observed_oci.items()
                                    if ocid.split(".")[1] == kind]
                            return subprocess.CompletedProcess(argv, 0, json.dumps({"data": rows}), "")
                        assert argv[10] == "get" and argv[-1] in observed_oci
                        return subprocess.CompletedProcess(
                            argv, 0, json.dumps({"data": observed_oci[argv[-1]]}), "",
                        )

                    apply_commands = []
                    apply_go_executed = {"value": False}
                    drifted_initial = {"original": None}

                    def gated_core_destroy(args, *, scratch_path, intent_callback,
                                           started_callback, heartbeat_callback,
                                           result_callback, provider_keyed_v2, **_kwargs):
                        assert args[0] == "/usr/bin/terraform" and args[1] in {"show", "apply"}
                        assert provider_keyed_v2 is True
                        assert scratch_path == Path(core_plan.evidence["runDirectory"])
                        apply_commands.append(tuple(args))
                        invocation = CommandIntent(
                            str(uuid4()), str(scratch_path),
                            hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                        )
                        started = StartedCommand(invocation, ProcessIdentity(
                            str(uuid4()), 5000 + len(apply_commands),
                            5000 + len(apply_commands), 5000 + len(apply_commands),
                        ))
                        intent_callback(invocation)
                        if (args[1] == "apply" and apply_case ==
                                "worker_success_initial_published_apply_drift"):
                            stored = SqlAlchemyJobRepository().get(parent.id)
                            drifted_initial["original"] = stored
                            SqlAlchemyJobRepository().save(replace(
                                stored, events=[*stored.events,
                                    JobEvent(len(stored.events) + 1, "info",
                                             "unreviewed event at held GO", {})],
                            ))
                        started_callback(started)
                        heartbeat_callback(started)
                        if args[1] == "apply":
                            apply_go_executed["value"] = True
                            assert any(argv[10] == "get" for argv in oci_calls)
                            applied = SqlAlchemyJobRepository().get(
                                f"job-provider-keyed-core-destroy-apply-{job.id.removeprefix('job-')}"
                            )
                            prestate = next(event.data for event in applied.events
                                            if event.message == "core destroy prestate identity fenced")
                            core_state_path.write_text(json.dumps({
                                "version": 4,
                                "terraform_version": core_plan.evidence["terraformFingerprint"],
                                "lineage": prestate["lineage"], "serial": prestate["serial"] + 1,
                                "outputs": {}, "resources": [],
                            }), encoding="utf-8")
                        output = shown_core if args[1] == "show" else ""
                        result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
                        return CommandResult(started, 0, output, "", False, False)

                    def visible_with_local_identity(observed, **options):
                        return prove_oci_core_visibility(
                            observed, **options, identity_reader=lambda: dict(identity),
                        )

                    apply_options = dict(
                        environment="devtest", state_root=sketch_state_root,
                        retired_recognizer=lambda *_a, **_kw: pytest.fail(
                            "pending recognizer substituted for published history"),
                        release_check=preview_options["release_check"],
                        gated_command_runner=gated_core_destroy,
                        visibility_prover=visible_with_local_identity,
                        oci_command_runner=oci_read_command, oci_executable=cli,
                    )
                    jobs = SqlAlchemyJobRepository()
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed later event", {})]))
                    with pytest.raises(core_destroy_apply.KeyedCoreDestroyApplyAttention):
                        core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                            teardown.id, **apply_options)
                    assert apply_commands == [] and oci_calls == []
                    jobs.save(original_initial)

                    if apply_case == "worker_success_initial_published_apply_drift":
                        with pytest.raises(core_destroy_apply.KeyedCoreDestroyApplyAttention):
                            core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                                teardown.id, **apply_options)
                        assert [args[1] for args in apply_commands] == ["show", "apply"]
                        assert drifted_initial["original"] is not None
                        assert apply_go_executed["value"] is False
                        assert core_state_path.read_bytes() == core_state_bytes
                        jobs.save(drifted_initial["original"])
                        child_id = ("job-provider-keyed-core-destroy-apply-"
                                    f"{job.id.removeprefix('job-')}")
                        nonreplayable = jobs.get(child_id)
                        assert nonreplayable is not None and nonreplayable.status == "running"
                        with pytest.raises(core_destroy_apply.KeyedCoreDestroyApplyAttention):
                            core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                                teardown.id, **{**apply_options,
                                    "gated_command_runner": lambda *_a, **_kw: pytest.fail(
                                        "interrupted apply replayed")})
                        assert jobs.get(child_id) == nonreplayable
                        assert [args[1] for args in apply_commands] == ["show", "apply"]
                        return

                    applied_core_destroy = core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                        teardown.id, **apply_options)
                    assert applied_core_destroy.status == "succeeded"
                    assert applied_core_destroy.events[-1].message == (
                        "core destroy applied; provider absence pending")
                    assert [args[1] for args in apply_commands] == ["show", "apply"]
                    prestate = next(event.data for event in applied_core_destroy.events
                                    if event.message == "core destroy prestate identity fenced")
                    assert prestate["resourceIds"] == {
                        row.address: row.ocid for row in core_inventory.resources
                    }
                    assert prestate["preDestroyStateSha256"] == hashlib.sha256(
                        core_state_bytes).hexdigest()
                    empty_state = json.loads(core_state_path.read_text())
                    assert empty_state["resources"] == [] and empty_state["outputs"] == {}
                    assert empty_state["lineage"] == core_inventory.lineage
                    assert empty_state["serial"] > core_inventory.serial

                oci_apply_reopen = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, oci_apply_reopen)), db.bind(oci_apply_reopen):
                    assert SqlAlchemyJobRepository().get(applied_core_destroy.id) == applied_core_destroy
                    with pytest.raises(core_destroy_apply.KeyedCoreDestroyApplyAttention):
                        core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                            teardown.id, **{**apply_options,
                                "gated_command_runner": lambda *_a, **_kw: pytest.fail(
                                    "one-shot OCI apply replayed")})
                    assert [args[1] for args in apply_commands] == ["show", "apply"]

                oci_absence_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, oci_absence_restart)), db.bind(oci_absence_restart):
                    monkeypatch.setattr(core_destroy_absence, "DEFAULT_TERRAFORM_STATE_ROOT", state_root)
                    absence_calls = []

                    def absent_oci_command(argv, env):
                        absence_calls.append(tuple(argv))
                        assert argv[:8] == (
                            str(cli), "--auth", "instance_principal", "--region",
                            target["region"], "--output", "json", "--no-retry",
                        )
                        assert env["HOME"] == "/nonexistent"
                        if argv[10] == "list":
                            return subprocess.CompletedProcess(
                                argv, 0, json.dumps({"data": []}), "",
                            )
                        assert argv[10] == "get" and argv[-1] in observed_oci
                        return subprocess.CompletedProcess(
                            argv, 1, "",
                            'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}',
                        )

                    absence_options = dict(
                        environment="devtest", state_root=sketch_state_root,
                        oci_command_runner=absent_oci_command,
                        identity_reader=lambda: dict(identity),
                        max_scans=2, poll_seconds=0, pause=lambda _seconds: None,
                    )
                    jobs = SqlAlchemyJobRepository()
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed pre-absence event", {})]))
                    with pytest.raises(core_destroy_absence.KeyedCoreDestroyAbsenceAttention):
                        core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                            teardown.id, **absence_options)
                    assert absence_calls == []
                    jobs.save(original_initial)

                    absent_core = core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                        teardown.id, **absence_options)
                    assert absent_core.status == "succeeded"
                    assert absent_core.events[-1].message == "core destroy exact absence proved"
                    assert absent_core.events[-1].data["emptyStateSha256"] == hashlib.sha256(
                        core_state_path.read_bytes()).hexdigest()
                    assert absent_core.events[-1].data["preDestroyResourceIdsSha256"] == (
                        prestate["resourceIdsSha256"])
                    assert absent_core.events[-1].data["ociAbsenceWitness"]["phase"] == "absent"
                    per_scan = len({_OCI_ROLES[row.address][0] for row in core_inventory.resources})
                    assert len([argv for argv in absence_calls if argv[10] == "list"]) == 2 * per_scan
                    assert len([argv for argv in absence_calls if argv[10] == "get"]) == (
                        2 * len(core_inventory.resources))

                oci_absence_reopen = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, oci_absence_reopen)), db.bind(oci_absence_reopen):
                    assert SqlAlchemyJobRepository().get(absent_core.id) == absent_core
                    assert core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                        teardown.id, **absence_options) == absent_core
                    assert len([argv for argv in absence_calls if argv[10] == "get"]) == (
                        2 * len(core_inventory.resources))
                    jobs = SqlAlchemyJobRepository()
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed post-absence event", {})]))
                    with pytest.raises(core_destroy_absence.KeyedCoreDestroyAbsenceAttention):
                        core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                            teardown.id, **absence_options)
                    assert len([argv for argv in absence_calls if argv[10] == "get"]) == (
                        2 * len(core_inventory.resources))
                    jobs.save(original_initial)

                inspector_negative_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, inspector_negative_restart)), db.bind(inspector_negative_restart):
                    monkeypatch.setattr(core_destroy_absence, "_default_identity_reader",
                                        lambda: dict(identity))
                    monkeypatch.setattr(inspector_negative, "recognize_pending_keyed_group_retired",
                                        lambda *_a, **_kw: pytest.fail(
                                            "pending group recognizer substituted for published history"))
                    negative_targets = snapshot["publicVerificationTargets"]
                    assert negative_targets
                    control = {"id": "inspector-external-control", "type": "tcp",
                               "host": "4.2.2.2", "port": 443}
                    probe_rounds = []

                    class InspectorReadOnlyProbe:
                        def run(self, *, host, ssh_key, spec):
                            assert host.provider == "linode" and host.resource_id == "12345"
                            assert ssh_key.private_key_path == str(inspector_key_path)
                            assert ssh_key.public_key.split()[:2] == inspector_public.split()[:2]
                            assert spec == {"positive": [control], "negative": negative_targets,
                                            "timeoutSeconds": 8, "strictNegativeTcp": True}
                            probe_rounds.append(spec)
                            return {"ok": True, "results": [
                                {"id": control["id"], "type": "tcp", "ok": True,
                                 "expected": "reachable", "observed": ""},
                                *[{"id": row["id"], "type": row["type"], "ok": True,
                                   "expected": "closed", "observed": {
                                       "status": "closed", "reason": "connection_refused"}}
                                  for row in spec["negative"]],
                            ]}

                    fresh_catalog = _AbsentCatalog(scope["selectorTag"])

                    with pytest.raises(ProviderKeyedDestroyAbsencePreflightError):
                        reconcile_successful_digitalocean_destroy_absence(
                            teardown.id, environment="devtest", state_root=sketch_state_root,
                            transport=fresh_catalog, max_attempts=1,
                            poll_interval_seconds=0,
                        )
                    assert fresh_catalog.paths == []
                    jobs = SqlAlchemyJobRepository()
                    original_coordinator = jobs.get(coordinator.id)
                    changed_events = list(original_coordinator.events)
                    changed_events[-1] = replace(changed_events[-1], data={
                        **changed_events[-1].data,
                        "priorChainProjectionSha256": "0" * 64,
                    })
                    jobs.save(replace(original_coordinator, events=changed_events))
                    with pytest.raises(ProviderKeyedDestroyAbsencePreflightError):
                        reconcile_successful_digitalocean_destroy_absence(
                            teardown.id, environment="devtest", state_root=sketch_state_root,
                            transport=fresh_catalog, max_attempts=1,
                            poll_interval_seconds=0, retired_published=True,
                        )
                    assert fresh_catalog.paths == []
                    jobs.save(original_coordinator)

                    def fresh_do_absence(parent_job_id, **options):
                        return reconcile_successful_digitalocean_destroy_absence(
                            parent_job_id, **options, transport=fresh_catalog,
                            max_attempts=1, poll_interval_seconds=0,
                        )

                    negative_options = dict(
                        environment="devtest", state_root=sketch_state_root,
                        runner=InspectorReadOnlyProbe(), positive_control=control,
                        do_absence_reader=fresh_do_absence,
                        oci_absence_recognizer=lambda *_a, **_kw: pytest.fail(
                            "injected pending OCI recognizer authorized published history"),
                    )
                    jobs = SqlAlchemyJobRepository()
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed pre-Inspector event", {})]))
                    with pytest.raises(inspector_negative.KeyedInspectorNegativeAttention):
                        prove_pending_keyed_inspector_negative(teardown.id, **negative_options)
                    assert probe_rounds == [] and fresh_catalog.paths == []
                    jobs.save(original_initial)

                    negative_proof = prove_pending_keyed_inspector_negative(
                        teardown.id, **negative_options)
                    assert negative_proof.status == "succeeded"
                    assert negative_proof.input["ociAbsenceJobId"] == absent_core.id
                    assert negative_proof.events[-1].message == (
                        "inspector exact public negative proved")
                    assert len(negative_proof.events[-1].data["rounds"]) == 2
                    assert len(probe_rounds) == 2
                    assert len(fresh_catalog.paths) == 10

                inspector_negative_reopen = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, inspector_negative_reopen)), db.bind(inspector_negative_reopen):
                    class NoProbeReplay:
                        def run(self, **_kwargs):
                            pytest.fail("saved Inspector proof replayed a public probe")

                    assert prove_pending_keyed_inspector_negative(
                        teardown.id, **{**negative_options, "runner": NoProbeReplay()}
                    ) == negative_proof
                    assert len(probe_rounds) == 2
                    assert len(fresh_catalog.paths) == 15
                    jobs = SqlAlchemyJobRepository()
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed post-Inspector event", {})]))
                    with pytest.raises(inspector_negative.KeyedInspectorNegativeAttention):
                        prove_pending_keyed_inspector_negative(
                            teardown.id, **{**negative_options, "runner": NoProbeReplay()})
                    assert len(probe_rounds) == 2
                    assert len(fresh_catalog.paths) == 15
                    jobs.save(original_initial)

                selector_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, selector_restart)), db.bind(selector_restart):
                    class CompleteSelectorCatalog:
                        def __init__(self):
                            self.tag_present = True
                            self.paths = []

                        def request(self, origin, method, path, token):
                            assert origin == selector_retirement._ORIGIN
                            assert method == "GET" and token == "fixture-token"
                            self.paths.append(path)
                            if path == f"/tags/{scope['selectorTag']}":
                                assert self.tag_present
                                return {"tag": {"name": scope["selectorTag"],
                                                "resources": {"count": 0}}}
                            endpoint = path.split("?", 1)[0]
                            assert endpoint in {
                                "/droplets", "/images", "/volumes", "/snapshots",
                                "/firewalls", "/account/keys", "/tags",
                            }
                            key = "ssh_keys" if endpoint == "/account/keys" else endpoint.removeprefix("/")
                            if endpoint == "/snapshots":
                                assert path == "/snapshots?page=1&per_page=200&resource_type=volume"
                                return {"snapshots": None, "meta": {"total": 0}, "links": {}}
                            rows = ([{"name": scope["selectorTag"],
                                      "resources": {"count": 0}}]
                                    if endpoint == "/tags" and self.tag_present else [])
                            return {key: rows, "meta": {"total": len(rows)},
                                    "links": {"pages": {}}}

                    class GuardedSelectorDelete:
                        def __init__(self, catalog):
                            self.catalog = catalog
                            self.deletes = 0
                            self.status_reads = 0

                        def delete_tag(self, token, selector):
                            assert token == "fixture-token" and selector == scope["selectorTag"]
                            assert self.catalog.tag_present and self.deletes == 0
                            self.deletes += 1
                            self.catalog.tag_present = False
                            if apply_case == "worker_success_initial_published_selector_ambiguous":
                                raise selector_retirement.SelectorRetirementAttention(
                                    "simulated lost DELETE response")
                            return selector_retirement.DeleteResponse(204, b"")

                        def get_tag_status(self, token, selector):
                            assert token == "fixture-token" and selector == scope["selectorTag"]
                            self.status_reads += 1
                            return 404 if not self.catalog.tag_present else 200

                    selector_catalog = CompleteSelectorCatalog()
                    selector_delete = GuardedSelectorDelete(selector_catalog)
                    selector_options = dict(
                        environment="devtest", state_root=sketch_state_root,
                        retired_recognizer=lambda *_a, **_kw: pytest.fail(
                            "pending group recognizer authorized published selector"),
                        core_absence_recognizer=lambda *_a, **_kw: pytest.fail(
                            "pending OCI recognizer authorized published selector"),
                        catalog_transport=selector_catalog, delete_transport=selector_delete,
                    )
                    jobs = SqlAlchemyJobRepository()
                    original_negative = jobs.get(negative_proof.id)
                    jobs.save(replace(original_negative, status="failed"))
                    with pytest.raises(selector_retirement.SelectorRetirementAttention):
                        selector_retirement.retire_pending_digitalocean_selector(
                            teardown.id, **selector_options)
                    assert selector_delete.deletes == 0 and selector_catalog.paths == []
                    jobs.save(original_negative)

                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed pre-selector event", {})]))
                    with pytest.raises(selector_retirement.SelectorRetirementAttention):
                        selector_retirement.retire_pending_digitalocean_selector(
                            teardown.id, **selector_options)
                    assert selector_delete.deletes == 0 and selector_catalog.paths == []
                    jobs.save(original_initial)

                    if apply_case == "worker_success_initial_published_selector_ambiguous":
                        with pytest.raises(selector_retirement.SelectorRetirementAttention):
                            selector_retirement.retire_pending_digitalocean_selector(
                                teardown.id, **selector_options)
                        uncertain = SqlAlchemyJobRepository().get(
                            f"job-provider-keyed-selector-retirement-{job.id.removeprefix('job-')}")
                        assert uncertain.status == "running"
                        assert uncertain.events[-1].message == "selector DELETE intended"
                        assert selector_delete.deletes == 1
                        SqlAlchemyJobRepository().save(replace(uncertain, input={
                            **uncertain.input,
                            "claimExpiresAt": (datetime.now(timezone.utc)
                                               - timedelta(seconds=1)).isoformat(),
                        }))
                        selector_child = selector_retirement.retire_pending_digitalocean_selector(
                            teardown.id, **selector_options)
                    else:
                        selector_child = selector_retirement.retire_pending_digitalocean_selector(
                            teardown.id, **selector_options)
                    assert selector_child.status == "succeeded"
                    assert [event.message for event in selector_child.events] == [
                        "selector retirement queued", "selector retirement started",
                        "selector DELETE intended", (
                            "selector absence reconciled" if apply_case ==
                            "worker_success_initial_published_selector_ambiguous"
                            else "selector DELETE 204 received"),
                    ]
                    assert selector_child.input["inspectorNegativeJobId"] == negative_proof.id
                    assert selector_child.input["inspectorNegativeJournalSha256"] == (
                        job_event_digest(negative_proof.events))
                    assert selector_child.events[2].data["inspectorNegativeJobId"] == negative_proof.id
                    assert selector_delete.deletes == 1
                    assert selector_delete.status_reads == (
                        1 if apply_case == "worker_success_initial_published_selector_ambiguous" else 0)

                selector_reopen = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, selector_reopen)), db.bind(selector_reopen):
                    assert selector_retirement.recognize_pending_digitalocean_selector_retired(
                        teardown.id, **{key: value for key, value in selector_options.items()
                                        if key != "delete_transport"},
                        status_transport=selector_delete) == selector_child
                    assert selector_delete.deletes == 1
                    assert selector_delete.status_reads == (
                        3 if apply_case == "worker_success_initial_published_selector_ambiguous" else 2)
                    with pytest.raises(selector_retirement.SelectorRetirementAttention):
                        selector_retirement.retire_pending_digitalocean_selector(
                            teardown.id, **selector_options)
                    assert selector_delete.deletes == 1

                cleanup_preview_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, cleanup_preview_restart)), db.bind(cleanup_preview_restart):
                    settings = SqlAlchemyObserverSettingsRepository().get(engagement.id)
                    host = observer_checks._inspector_host_from_settings(
                        settings.current_host, settings=settings,
                    )
                    assert host is not None and host.resource_id == "12345"
                    firewall = host.metadata["providerFirewall"]
                    linode_gets = []

                    class PublishedLinodeReads:
                        host_live = True
                        firewall_live = True

                        def request(self, method, path, token):
                            linode_gets.append((method, path))
                            assert method == "GET" and token == "fixture-linode-token"
                            if ((path == "/linode/instances/12345" and not self.host_live)
                                    or (path == "/networking/firewalls/67890"
                                        and not self.firewall_live)):
                                try:
                                    raise urllib.error.HTTPError(path, 404, "absent", {}, None)
                                except urllib.error.HTTPError as exc:
                                    raise LinodeValidationError("external fixture 404") from exc
                            if path in {
                                "/linode/instances?page=1&page_size=100",
                                "/networking/firewalls?page=1&page_size=100",
                                "/networking/firewalls/67890/devices?page=1&page_size=100",
                            }:
                                visible = (self.host_live if path.startswith("/linode")
                                           or "/devices?" in path else self.firewall_live)
                                identifier = 12345 if visible and (
                                    path.startswith("/linode") or "/devices?" in path) else 67890
                                rows = ([{"id": identifier}] if visible else [])
                                if "/devices?" in path:
                                    rows = ([{"entity": {"type": "linode", "id": 12345}}]
                                            if self.host_live else [])
                                return {"data": rows, "page": 1, "pages": 1,
                                        "results": len(rows)}
                            bodies = {
                                "/linode/instances/12345": {
                                    "id": 12345, "label": host.name, "region": host.region,
                                    "type": settings.size, "status": "running",
                                    "ipv4": [host.public_ip], "tags": ["barragan", "inspector"],
                                },
                                "/networking/firewalls/67890": {
                                    "id": 67890, "label": firewall["name"], "status": "enabled",
                                },
                                "/networking/firewalls/67890/rules": {
                                    "inbound_policy": "DROP", "outbound_policy": "ACCEPT",
                                    "inbound": [{"action": "ACCEPT", "protocol": "TCP",
                                                 "ports": "22", "addresses": {
                                                     "ipv4": [firewall["managementSourceCidr"]]}}],
                                    "outbound": [],
                                },
                            }
                            assert path in bodies
                            return bodies[path]

                    published_linode_reads = PublishedLinodeReads()
                    cleanup_options = dict(
                        environment="devtest", state_root=sketch_state_root,
                        transport=published_linode_reads,
                        do_catalog_transport=selector_catalog,
                        selector_status_transport=selector_delete,
                        negative_recognizer=lambda *_a, **_kw: pytest.fail(
                            "pending negative recognizer authorized published preview"),
                        readiness_recognizer=lambda *_a, **_kw: pytest.fail(
                            "injected readiness recognizer authorized published preview"),
                    )
                    jobs = SqlAlchemyJobRepository()
                    original_initial = jobs.get(parent.id)
                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed pre-cleanup event", {})]))
                    with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                        linode_cleanup.preview_pending_linode_inspector_cleanup(
                            teardown.id, **cleanup_options)
                    assert linode_gets == []
                    jobs.save(original_initial)

                    original_negative = jobs.get(negative_proof.id)
                    jobs.save(replace(original_negative, status="failed"))
                    with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                        linode_cleanup.preview_pending_linode_inspector_cleanup(
                            teardown.id, **cleanup_options)
                    assert linode_gets == []
                    jobs.save(original_negative)

                    original_selector = jobs.get(selector_child.id)
                    jobs.save(replace(original_selector, events=[*original_selector.events,
                        JobEvent(len(original_selector.events) + 1, "info",
                                 "unreviewed selector event", {})]))
                    with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                        linode_cleanup.preview_pending_linode_inspector_cleanup(
                            teardown.id, **cleanup_options)
                    assert linode_gets == []
                    jobs.save(original_selector)

                    cleanup_preview = linode_cleanup.preview_pending_linode_inspector_cleanup(
                        teardown.id, **cleanup_options)
                    assert cleanup_preview.origin == "retained"
                    assert cleanup_preview.host_record_id == "linode:inspector:12345"
                    assert cleanup_preview.firewall_record_id == "linode:inspector-firewall:67890"
                    assert cleanup_preview.negative_job_id == negative_proof.id
                    assert len(linode_gets) == 6
                    assert selector_delete.deletes == 1

                    class PublishedLinodeDeletes:
                        def __init__(self):
                            self.paths = []
                            self.lose_host_response = (
                                apply_case == "worker_success_initial_published_selector_ambiguous")

                        def delete(self, path, token):
                            assert token == "fixture-linode-token"
                            assert path in {
                                "/linode/instances/12345",
                                "/networking/firewalls/67890",
                            }
                            self.paths.append(path)
                            if path == "/linode/instances/12345":
                                assert self.paths == [path]
                                published_linode_reads.host_live = False
                                if self.lose_host_response:
                                    self.lose_host_response = False
                                    raise TimeoutError("injected lost host DELETE response")
                            else:
                                assert self.paths == [
                                    "/linode/instances/12345", path]
                                published_linode_reads.firewall_live = False
                            return linode_cleanup.LinodeDeleteResponse(200, b"{}")

                    published_linode_deletes = PublishedLinodeDeletes()
                    def run_published_cleanup():
                        return linode_cleanup.retire_pending_linode_inspector(
                            teardown.id, environment="devtest", state_root=sketch_state_root,
                            read_transport=published_linode_reads,
                            delete_transport=published_linode_deletes,
                            sleep=lambda _seconds: pytest.fail(
                                "fixture absence unexpectedly waited"),
                            do_catalog_transport=selector_catalog,
                            selector_catalog_transport=selector_catalog,
                            selector_status_transport=selector_delete,
                            preview_reader=lambda *_a, **_kw: pytest.fail(
                                "pending preview authorized published cleanup"),
                            group_reader=lambda *_a, **_kw: pytest.fail(
                                "pending group authorized published cleanup"),
                            oci_reader=lambda *_a, **_kw: pytest.fail(
                                "pending OCI authorized published cleanup"),
                            negative_reader=lambda *_a, **_kw: pytest.fail(
                                "pending negative authorized published cleanup"),
                            selector_reader=lambda *_a, **_kw: pytest.fail(
                                "pending selector authorized published cleanup"),
                        )

                    jobs.save(replace(original_initial, events=[*original_initial.events,
                        JobEvent(len(original_initial.events) + 1, "info",
                                 "unreviewed pre-delete event", {})]))
                    with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                        run_published_cleanup()
                    assert published_linode_deletes.paths == []
                    jobs.save(original_initial)

                    before_rows = SqlAlchemyProviderResourceRepository().list_for_engagement(
                        engagement.id)
                    before_settings = SqlAlchemyObserverSettingsRepository().get(engagement.id)
                    if apply_case == "worker_success_initial_published_selector_ambiguous":
                        with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                            run_published_cleanup()
                        interrupted = jobs.get(
                            f"job-provider-keyed-inspector-linode-cleanup-"
                            f"{job.id.removeprefix('job-')}")
                        assert interrupted.events[-1].message == "inspector host DELETE intended"
                        assert published_linode_deletes.paths == ["/linode/instances/12345"]
                    else:
                        from app.services import engagement_lifecycle as lifecycle_service

                        original_resolver = lifecycle_service.resolve_engagement_lifecycle

                        def fail_local_final_commit(*_args, **_kwargs):
                            staged = SqlAlchemyProviderResourceRepository().list_for_engagement(
                                engagement.id)
                            assert all(row.status == "destroyed" for row in staged)
                            raise RuntimeError("injected local final-commit failure")

                        monkeypatch.setattr(lifecycle_service, "resolve_engagement_lifecycle",
                                            fail_local_final_commit)
                        try:
                            with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                                run_published_cleanup()
                        finally:
                            monkeypatch.setattr(lifecycle_service,
                                                "resolve_engagement_lifecycle",
                                                original_resolver)
                        assert published_linode_deletes.paths == [
                            "/linode/instances/12345", "/networking/firewalls/67890"]
                        assert SqlAlchemyProviderResourceRepository().list_for_engagement(
                            engagement.id) == before_rows
                        assert SqlAlchemyObserverSettingsRepository().get(
                            engagement.id) == before_settings
                        assert jobs.get(teardown.id).status == "queued"
                        assert _db_lease_lookup(engagement.id) == (
                            plan.id, "provider_keyed_teardown_fence")
                        from app.storage.models import JobRunModel
                        from sqlalchemy import update
                        import inspect

                        original_history = linode_cleanup._published_retired_authority
                        injected_final_drift = []
                        before_parent = jobs.get(teardown.id)

                        def drift_inside_final_writer(*args, **kwargs):
                            if inspect.stack()[1].function == "_finish_atomic":
                                parent_before = jobs.get(teardown.id)
                                changed_source = {
                                    **parent_before.input["publishedSource"],
                                    "state_sha256": "0" * 64,
                                }
                                db.session.execute(update(JobRunModel).where(
                                    JobRunModel.id == teardown.id,
                                ).values(input={**parent_before.input,
                                                "publishedSource": changed_source}))
                                injected_final_drift.append(True)
                            return original_history(*args, **kwargs)

                        monkeypatch.setattr(linode_cleanup, "_published_retired_authority",
                                            drift_inside_final_writer)
                        try:
                            with pytest.raises(linode_cleanup.LinodeInspectorCleanupAttention):
                                run_published_cleanup()
                        finally:
                            monkeypatch.setattr(linode_cleanup,
                                                "_published_retired_authority",
                                                original_history)
                        assert injected_final_drift == [True]
                        assert jobs.get(teardown.id) == before_parent
                        assert SqlAlchemyProviderResourceRepository().list_for_engagement(
                            engagement.id) == before_rows
                        assert SqlAlchemyObserverSettingsRepository().get(
                            engagement.id) == before_settings
                        assert published_linode_deletes.paths == [
                            "/linode/instances/12345", "/networking/firewalls/67890"]
                    terminal = run_published_cleanup()
                    assert terminal.status == "succeeded"
                    assert published_linode_deletes.paths == [
                        "/linode/instances/12345", "/networking/firewalls/67890"]
                terminal_restart = db.configure(state.uri)
                with runtime_context(configure_runtime(runtime_settings, terminal_restart)), db.bind(terminal_restart):
                    assert linode_cleanup.recognize_pending_linode_inspector_retired(
                        teardown.id, environment="devtest") == terminal
                    assert run_published_cleanup() == terminal
                    assert published_linode_deletes.paths == [
                        "/linode/instances/12345", "/networking/firewalls/67890"]
                    if sealed_cleanup_service_id is not None:
                        from app.storage.service_repository import SqlAlchemyEngagementServiceRepository
                        service = SqlAlchemyEngagementServiceRepository().get(engagement.id, sealed_cleanup_service_id)
                        assert service.status == "Retired" and service.apply_job_id
                        assert SqlAlchemyJobRepository().get(teardown.id).status == "succeeded"
                return

            scheduled_pending = []
            if apply_case == "worker_success_initial_dispatch_core_apply":
                from app.asgi import create_app
                from app.core.config import TestConfig

                class PendingDevTest(TestConfig):
                    ENVIRONMENT = "devtest"
                    SQLALCHEMY_DATABASE_URI = state.uri
                    DATA_DIR = Path(runtime_settings["DATA_DIR"])
                    PROVIDER_KEYED_TEMPLATE_ROOT = str(pinned)
                    PROVIDER_KEYED_INSPECTOR_CONTROL_IPV4 = "4.2.2.2"
                    PROVIDER_KEYED_INITIAL_DISPATCH_ENABLED = False

                app = create_app(PendingDevTest)
                real_pending_advance = pending_dispatch.advance_pending_keyed_terminal
                monkeypatch.setattr(
                    pending_dispatch, "advance_pending_keyed_terminal",
                    lambda *_args, **_kwargs: run_private_dispatch(),
                )
                monkeypatch.setattr(
                    "app.core.runtime.start_runtime_task",
                    lambda task, *, name, **_kwargs: scheduled_pending.append((task, name)),
                )
                route = f"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/{job.id}/teardown"
                response = app.test_client().get(route)
                assert response.status_code == 200
                preview = response.get_json()["teardown"]
            else:
                preview = preview_engagement_teardown(job.id)
            assert preview is not None and preview["snapshotId"]
            assert preview["engagementId"] == engagement.id
            if apply_case == "worker_success_initial_dispatch_core_apply":
                response = app.test_client().post(route, json={
                    "confirmation": preview["confirmationPhrase"],
                    "snapshotId": preview["snapshotId"],
                })
                assert response.status_code == 200
                reviewed_parent = SqlAlchemyJobRepository().get(_parent_id(job.id))
                assert response.get_json()["job"]["id"] == reviewed_parent.id
                assert [name for _task, name in scheduled_pending] == [
                    "barragan-keyed-pending-teardown"]
                repeated = app.test_client().post(route, json={
                    "confirmation": preview["confirmationPhrase"],
                    "snapshotId": preview["snapshotId"],
                })
                assert repeated.status_code == 200
                assert repeated.get_json()["job"]["id"] == reviewed_parent.id
                assert len(scheduled_pending) == 2
            else:
                reviewed_parent = start_engagement_teardown(
                    job.id, {"confirmation": preview["confirmationPhrase"],
                             "snapshotId": preview["snapshotId"]},
                    provider_keyed_environment="devtest",
                    provider_keyed_coordinator=lambda queued_id: run_provider_keyed_comprehensive_handoff(
                        queued_id, environment="devtest", state_root=sketch_state_root,
                    ),
                )
            assert reviewed_parent.status == "queued" and reviewed_parent.input["phase"] == "queued"
            snapshot = reviewed_parent.input["scopeSnapshot"]
            assert snapshot["providerScopes"] == [scope]
            assert snapshot["inspector"]["tracked"] is True
            assert set(snapshot["inspector"]["ownedProviderRecordIds"]) == {
                record.id for record in records_before
            }
            coordinator_id = f"job-provider-keyed-comprehensive-teardown-{job.id.removeprefix('job-')}"
            coordinator = SqlAlchemyJobRepository().get(coordinator_id)
            assert coordinator.status == "running"
            assert coordinator.input["phase"] == "awaiting_inspector_preflight"
            assert SqlAlchemyJobRepository().get(parent.id).input["phase"] == "teardown_handoff_pending"
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

            assert SqlAlchemyJobRepository().get(job.id) == core_before
            assert SqlAlchemyDeploymentPlanRepository().get(plan.id) == plan_before
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert terraform_calls == ["version", "init", "plan", "show"]
            assert apply_calls == ["show", "apply"] and selector_post.calls == 1

        handoff_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, handoff_restart)), db.bind(handoff_restart):
            jobs = SqlAlchemyJobRepository()
            reviewed, selected_core, sealed, operation = _boundary(
                reviewed_parent.id, jobs, SqlAlchemyDeploymentPlanRepository(), _db_lease_lookup,
            )
            assert reviewed == reviewed_parent and selected_core == core_before
            assert sealed == snapshot and operation == "provider_keyed_teardown_fence"
            source = load_keyed_teardown_source(
                reviewed_parent.id, phase="pre_go", environment="devtest",
                state_root=sketch_state_root,
            )
            assert source.variant == "pending_handoff"
            assert source.core_job_id == job.id and source.initial_job_id == parent.id
            assert source.snapshot_id == snapshot["snapshotId"]
            inspector = inspect_prepared_keyed_teardown_inspector(
                reviewed_parent.id, environment="devtest",
            )
            assert inspector.provider == "linode" and inspector.provider_resource_id == "12345"
            assert inspector.owned_record_id == "linode:inspector:12345"
            assert inspector.scope_snapshot_id == snapshot["snapshotId"]
            saved_rows = (jobs.get(reviewed_parent.id), jobs.get(coordinator_id),
                          jobs.get(parent.id), SqlAlchemyObserverSettingsRepository().get(engagement.id),
                          SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id))
            residual_keys = Path(evidence.scratch_paths[0]) / "keys"
            residual_keys.mkdir(mode=0o700)
            try:
                with pytest.raises(ProviderKeyedTeardownSourceError):
                    load_keyed_teardown_source(
                        reviewed_parent.id, phase="pre_go", environment="devtest",
                        state_root=sketch_state_root,
                    )
            finally:
                residual_keys.rmdir()
            assert (jobs.get(reviewed_parent.id), jobs.get(coordinator_id),
                    jobs.get(parent.id), SqlAlchemyObserverSettingsRepository().get(engagement.id),
                    SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id)) == saved_rows
            assert load_keyed_teardown_source(
                reviewed_parent.id, phase="pre_go", environment="devtest",
                state_root=sketch_state_root,
            ) == source
            assert terraform_calls == ["version", "init", "plan", "show"]
            assert apply_calls == ["show", "apply"] and selector_post.calls == 1

        # The retained Inspector has to be proved again under the teardown
        # fence. Only the exact provider GETs and read-only SSH subprocesses
        # are simulated; the boundary, provider parser, SSH policy reader,
        # claim journal, and saved-success recognizer remain real.
        proof_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, proof_restart)), db.bind(proof_restart):
            settings = SqlAlchemyObserverSettingsRepository().get(engagement.id)
            host = observer_checks._inspector_host_from_settings(
                settings.current_host, settings=settings,
            )
            assert host is not None
            firewall = host.metadata["providerFirewall"]
            proof_gets = []

            class RetainedLinodeReads:
                def request(self, method, path, token):
                    proof_gets.append((method, path))
                    assert method == "GET" and token == "fixture-linode-token"
                    bodies = {
                        "/linode/instances/12345": {
                            "id": 12345, "label": host.name, "region": host.region,
                            "type": settings.size, "status": "running",
                            "ipv4": [host.public_ip], "tags": ["barragan", "inspector"],
                        },
                        "/networking/firewalls/67890": {
                            "id": 67890, "label": firewall["name"], "status": "enabled",
                        },
                        "/networking/firewalls/67890/rules": {
                            "inbound_policy": "DROP", "outbound_policy": "ACCEPT",
                            "inbound": [{
                                "action": "ACCEPT", "protocol": "TCP", "ports": "22",
                                "addresses": {"ipv4": ["8.8.8.8/32"]},
                            }], "outbound": [],
                        },
                        "/networking/firewalls/67890/devices?page=1&page_size=100": {
                            "data": [{"entity": {"type": "linode", "id": 12345}}],
                            "page": 1, "pages": 1, "results": 1,
                        },
                    }
                    assert path in bodies
                    return bodies[path]

            before_proof_hosts = len(inspector_host_commands)
            before_proof_fences = len(proof_fence_calls)
            # The proof module holds its own import of _run_checked; fencing
            # observer_checks alone would permit a real SSH process here.
            monkeypatch.setattr(inspector_ssh_proof, "_run_checked", host_run)
            real_run = subprocess.run
            external_processes = []

            def key_verification_only(command, *args, **kwargs):
                external_processes.append(tuple(command))
                assert command == ["/usr/bin/ssh-keygen", "-y", "-P", "", "-f",
                                   str(inspector_key_path)]
                return real_run(command, *args, **kwargs)

            monkeypatch.setattr(subprocess, "run", key_verification_only)
            try:
                retained_ready = prove_retained_keyed_inspector_ready(
                    reviewed_parent.id, environment="devtest",
                    management_source_resolver=lambda: "8.8.8.8/32",
                    transport=RetainedLinodeReads(),
                )
            finally:
                monkeypatch.setattr(subprocess, "run", real_run)
            assert external_processes and all(command[0] == "/usr/bin/ssh-keygen"
                                              for command in external_processes)
            expected_gets = [("GET", path) for path in (
                "/linode/instances/12345", "/networking/firewalls/67890",
                "/networking/firewalls/67890/rules",
                "/networking/firewalls/67890/devices?page=1&page_size=100",
            )]
            assert proof_gets == expected_gets
            proof_ssh = inspector_host_commands[before_proof_hosts:]
            assert len(proof_ssh) == 5
            assert proof_ssh[0][-3:] == ("sudo", "-n", "true")
            assert proof_ssh[1][-2:] == ("/usr/bin/printenv", "SSH_CONNECTION")
            assert proof_ssh[2][-3:] == (
                "-T", "-C", "user=root,addr=8.8.8.8,host=8.8.8.8",
            )
            assert proof_ssh[3][-2:] == ("root@45.79.201.25", "true")
            assert proof_ssh[4][-2:] == ("/usr/bin/nmap", "--version")
            assert proof_fence_calls[before_proof_fences:] == ["before", "after"] * 5
            ready_child = SqlAlchemyJobRepository().get(coordinator_id)
            assert ready_child.input["phase"] == "inspector_ready"
            assert len(ready_child.events) == 5
            assert ready_child.events[-1].message == "retained_inspector_ready"
            assert retained_ready.coordinator_job_id == ready_child.id
            assert SqlAlchemyJobRepository().get(reviewed_parent.id) == reviewed_parent
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        ready_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, ready_restart)), db.bind(ready_restart):
            assert recognize_retained_keyed_inspector_ready(
                reviewed_parent.id, environment="devtest",
            ) == retained_ready
            assert proof_gets == expected_gets
            assert len(inspector_host_commands) == before_proof_hosts + 5

        preview_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, preview_restart)), db.bind(preview_restart):
            destroy_shown = _destroy_shown_plan(workspace_path)
            destroy_commands = []
            membership_catalog = _AttachmentCatalog(attachment_intent)

            def destroy_command(args, *, scratch_path, provider_keyed_v2,
                                intent_callback, started_callback,
                                heartbeat_callback, result_callback, **_kwargs):
                phase = args[1]
                assert args[0] == "/usr/bin/terraform"
                assert phase in {"version", "init", "plan", "show"}
                assert provider_keyed_v2 is True and scratch_path == workspace_path
                destroy_commands.append(phase)
                invocation = CommandIntent(
                    str(uuid4()), str(scratch_path),
                    hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                )
                process_id = 3000 + len(destroy_commands)
                started = StartedCommand(invocation, ProcessIdentity(
                    str(uuid4()), process_id, process_id, process_id,
                ))
                intent_callback(invocation)
                started_callback(started)
                heartbeat_callback(started)
                if phase == "plan":
                    plan_path = Path(next(arg[5:] for arg in args if arg.startswith("-out=")))
                    assert plan_path.is_file()
                    plan_path.write_bytes(b"opaque complete destroy plan fixture")
                payload = (json.dumps({"terraform_version": "1.15.5"}) if phase == "version"
                           else destroy_shown if phase == "show" else "")
                result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
                return CommandResult(started, 0, payload, "", False, False)

            def write_destroy_preview(parent_job_id, **options):
                return run_digitalocean_initial_destroy_plan_job(
                    parent_job_id, **options, gated_command_runner=destroy_command,
                )

            def read_destroy_preview(parent_job_id, **options):
                return preflight_digitalocean_initial_destroy_apply(
                    parent_job_id, **options, membership_transport=membership_catalog,
                )

            preview_options = {
                "environment": "devtest", "state_root": sketch_state_root,
                "preview_runner": write_destroy_preview,
                "preview_recognizer": read_destroy_preview,
            }
            destroy_preview = run_provider_keyed_destroy_preview_from_ready(
                reviewed_parent.id, **preview_options,
            )
            destroy_plan_path = workspace_path / ".barragan-initial-destroy.tfplan"
            assert destroy_preview.status == "succeeded"
            assert destroy_preview.artifact_refs == [str(destroy_plan_path)]
            assert len(destroy_preview.events) == 16
            assert destroy_preview.events[-1].message == (
                "reviewed full-state provider destroy plan saved"
            )
            assert hashlib.sha256(destroy_plan_path.read_bytes()).hexdigest() == (
                destroy_preview.events[-1].data["planSha256"]
            )
            assert destroy_commands == ["version", "init", "plan", "show"]
            membership_paths = [
                f"/droplets?page=1&per_page=200&tag_name={attachment_intent.selector_tag}",
                "/droplets?page=1&per_page=200&type=gpus",
                f"/firewalls/{attachment_intent.firewall_id}",
            ]
            assert membership_catalog.paths == membership_paths
            assert SqlAlchemyJobRepository().get(coordinator_id) == ready_child
            assert SqlAlchemyJobRepository().get(reviewed_parent.id) == reviewed_parent
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")
            assert proof_gets == expected_gets
            assert len(inspector_host_commands) == before_proof_hosts + 5

        preview_read_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, preview_read_restart)), db.bind(preview_read_restart):
            saved_boundary = read_destroy_preview(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
            )
            assert saved_boundary.preview_job_id == destroy_preview.id
            assert saved_boundary.preview.plan_path == destroy_plan_path
            assert membership_catalog.paths == membership_paths * 2
            assert run_provider_keyed_destroy_preview_from_ready(
                reviewed_parent.id, **preview_options,
            ) == destroy_preview
            assert membership_catalog.paths == membership_paths * 3
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert SqlAlchemyJobRepository().get(coordinator_id) == ready_child

        apply_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, apply_restart)), db.bind(apply_restart):
            absent_catalog = _AbsentCatalog(intent.selector_tag)
            apply_commands = []
            live_proofs = []
            before_live_gets = len(proof_gets)
            before_live_hosts = len(inspector_host_commands)
            before_live_fences = len(proof_fence_calls)

            def live_inspector_proof(parent_job_id, **options):
                result = prove_live_keyed_inspector_before_destroy_go(
                    parent_job_id, **options,
                    source_resolver=lambda: "8.8.8.8/32",
                    transport_factory=lambda provider: (
                        RetainedLinodeReads() if provider == "linode"
                        else pytest.fail("unexpected Inspector provider")
                    ),
                )
                live_proofs.append(parent_job_id)
                return result

            def apply_command(args, *, scratch_path, provider_keyed_v2,
                              intent_callback, started_callback,
                              heartbeat_callback, result_callback, **_kwargs):
                phase = args[1]
                assert args[0] == "/usr/bin/terraform" and phase in {"show", "apply"}
                assert provider_keyed_v2 is True and scratch_path == workspace_path
                apply_commands.append(phase)
                invocation = CommandIntent(
                    str(uuid4()), str(scratch_path),
                    hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                )
                process_id = 4000 + len(apply_commands)
                started = StartedCommand(invocation, ProcessIdentity(
                    str(uuid4()), process_id, process_id, process_id,
                ))
                intent_callback(invocation)
                started_callback(started)
                heartbeat_callback(started)
                if phase == "apply":
                    assert live_proofs == [reviewed_parent.id]
                    retained_state = workspace_path / "terraform.tfstate"
                    before_state = json.loads(retained_state.read_text(encoding="utf-8"))
                    assert before_state["resources"]
                    retained_state.write_text(json.dumps({
                        **before_state, "serial": before_state["serial"] + 1,
                        "resources": [],
                    }), encoding="utf-8")
                    retained_state.chmod(0o600)
                payload = destroy_shown if phase == "show" else ""
                result_callback(CommandAuditResult(started, 0, len(payload), 0, False, False))
                return CommandResult(started, 0, payload, "", False, False)

            def run_destroy_apply(parent_job_id, **options):
                return run_digitalocean_initial_destroy_apply_job(
                    parent_job_id, **options,
                    membership_transport=membership_catalog,
                    live_inspector_prover=live_inspector_proof,
                    gated_command_runner=apply_command,
                    command_environment={},
                )

            def read_absence(parent_job_id, **options):
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_job_id, **options, transport=absent_catalog,
                    max_attempts=1, poll_interval_seconds=0,
                )

            # Only the real Inspector key-verification subprocess is allowed
            # while the real apply/absence services use fake external IO.
            real_run = subprocess.run
            subprocess_calls = []

            def key_verification_only(command, *args, **kwargs):
                subprocess_calls.append(tuple(command))
                assert command == ["/usr/bin/ssh-keygen", "-y", "-P", "", "-f",
                                   str(inspector_key_path)]
                return real_run(command, *args, **kwargs)

            monkeypatch.setattr(subprocess, "run", key_verification_only)
            try:
                absent = continue_digitalocean_keyed_destroy_apply(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    preview_recognizer=read_destroy_preview,
                    apply_runner=run_destroy_apply,
                    absence_reconciler=read_absence,
                )
            finally:
                monkeypatch.setattr(subprocess, "run", real_run)
            assert subprocess_calls and all(call[0] == "/usr/bin/ssh-keygen"
                                             for call in subprocess_calls)
            destroy_apply = SqlAlchemyJobRepository().get(
                f"job-provider-keyed-initial-destroy-apply-{job.id.removeprefix('job-')}"
            )
            assert destroy_apply.status == "succeeded"
            assert len(destroy_apply.events) == 12
            assert destroy_apply.events[-1].message == (
                "provider destroy apply completed; absence proof pending"
            )
            assert apply_commands == ["show", "apply"]
            assert live_proofs == [reviewed_parent.id]
            assert proof_gets[before_live_gets:] == expected_gets * 2
            assert len(inspector_host_commands) == before_live_hosts + 5
            assert proof_fence_calls[before_live_fences:] == ["before", "after"] * 5
            assert absent_catalog.paths == [
                "/droplets?page=1&per_page=200",
                "/droplets?page=1&per_page=200&type=gpus",
                "/firewalls?page=1&per_page=200",
                "/account/keys?page=1&per_page=200",
                "/tags?page=1&per_page=200",
            ]
            empty_state = json.loads((workspace_path / "terraform.tfstate").read_text())
            assert empty_state["resources"] == []
            assert empty_state["lineage"] == _applied_state(intent)["lineage"]
            assert empty_state["serial"] > _applied_state(intent)["serial"]
            assert absent.selector_tag_cleanup_pending is True
            assert absent.empty_state_sha256 == hashlib.sha256(
                (workspace_path / "terraform.tfstate").read_bytes(),
            ).hexdigest()
            assert membership_catalog.paths == membership_paths * 7
            assert SqlAlchemyJobRepository().get(coordinator_id) == ready_child
            assert SqlAlchemyJobRepository().get(reviewed_parent.id) == reviewed_parent
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        apply_read_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, apply_read_restart)), db.bind(apply_read_restart):
            def refuse_apply_replay(*_args, **_kwargs):
                pytest.fail("one-shot Terraform destroy apply replayed")

            repeated_absence = continue_digitalocean_keyed_destroy_apply(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                preview_recognizer=read_destroy_preview,
                apply_runner=refuse_apply_replay,
                absence_reconciler=read_absence,
            )
            assert repeated_absence == absent
            assert absent_catalog.paths == [
                "/droplets?page=1&per_page=200",
                "/droplets?page=1&per_page=200&type=gpus",
                "/firewalls?page=1&per_page=200",
                "/account/keys?page=1&per_page=200",
                "/tags?page=1&per_page=200",
            ] * 2
            assert membership_catalog.paths == membership_paths * 7
            assert apply_commands == ["show", "apply"]
            assert live_proofs == [reviewed_parent.id]

        absence_publish_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, absence_publish_restart)), db.bind(absence_publish_restart):
            inventory_paths = [
                "/droplets?page=1&per_page=200",
                "/droplets?page=1&per_page=200&type=gpus",
                "/firewalls?page=1&per_page=200",
                "/account/keys?page=1&per_page=200",
                "/tags?page=1&per_page=200",
            ]
            assert absent_catalog.paths == inventory_paths * 2

            def prove_absence(parent_job_id, **options):
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_job_id, **options, transport=absent_catalog,
                    poll_interval_seconds=0,
                )

            published_absence = publish_provider_keyed_destroy_absence(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                absence_preflight=prove_absence,
            )
            assert published_absence.id == coordinator_id
            assert published_absence.status == "running"
            assert published_absence.input["phase"] == "provider_absent"
            assert published_absence.events[:-1] == ready_child.events
            assert published_absence.events[-1].message == "provider_absent"
            assert published_absence.events[-1].data["applyJobId"] == destroy_apply.id
            assert published_absence.events[-1].data["previewJobId"] == destroy_preview.id
            assert published_absence.events[-1].data["selectorTagCleanupPending"] is True
            assert absent_catalog.paths == inventory_paths * 4
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"]
            assert SqlAlchemyJobRepository().get(reviewed_parent.id) == reviewed_parent
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        absence_read_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, absence_read_restart)), db.bind(absence_read_restart):
            assert recognize_provider_keyed_destroy_absence(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
            ) == published_absence
            assert absent_catalog.paths == inventory_paths * 4
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"]

        group_retirement_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, group_retirement_restart)), db.bind(group_retirement_restart):
            engagements = SqlAlchemyEngagementRepository()
            plans = SqlAlchemyDeploymentPlanRepository()
            chains_repo = SqlAlchemySketchChainRepository()
            desired_engagement = engagements.get(engagement.id)
            desired_plan = plans.get(plan.id)
            pending_rows = tuple(sorted(chains_repo.list_for_engagement(engagement.id),
                                        key=lambda row: row.chain_id))
            assert len(pending_rows) == 2
            assert all(row.status == "pending" and row.nodes == []
                       and not row.deploy_job_id and not row.terraform_working_directory
                       for row in pending_rows)
            retained_empty_state = (workspace_path / "terraform.tfstate").read_bytes()

            retired_rows = retire_pending_keyed_group_after_absence(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                absence_preflight=prove_absence,
            )
            retired_coordinator = SqlAlchemyJobRepository().get(coordinator_id)
            assert retired_coordinator.status == "running"
            assert retired_coordinator.input["phase"] == "pending_group_retired"
            assert retired_coordinator.events[:-1] == published_absence.events
            assert retired_coordinator.events[-1].message == "keyed_pending_provider_group_retired"
            assert retired_coordinator.events[-1].data["chainIds"] == sorted(
                row.chain_id for row in pending_rows
            )
            assert retired_coordinator.events[-1].data["retiredRecordIds"] == []
            assert retired_rows == tuple(sorted(chains_repo.list_for_engagement(engagement.id),
                                                key=lambda row: row.chain_id))
            for prior, retired in zip(pending_rows, retired_rows, strict=True):
                assert retired == replace(
                    prior, status="destroyed", nodes=[], teardown_job_id=destroy_apply.id,
                    updated_at=retired.updated_at,
                )
            assert absent_catalog.paths == inventory_paths * 5
            assert engagements.get(engagement.id) == desired_engagement
            assert plans.get(plan.id) == desired_plan
            assert (workspace_path / "terraform.tfstate").read_bytes() == retained_empty_state
            assert SqlAlchemyJobRepository().get(reviewed_parent.id) == reviewed_parent
            assert SqlAlchemyJobRepository().get(job.id) == core_before
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        group_read_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, group_read_restart)), db.bind(group_read_restart):
            assert recognize_pending_keyed_group_retired(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
            ) == retired_rows
            # Selector cleanup reads this common post-destroy boundary before
            # it calls the group recognizer. It must accept only the sealed
            # retired rows after restart, without replaying Terraform or GETs.
            selector_boundary = selector_retirement._read_success_boundary(
                reviewed_parent.id, jobs=SqlAlchemyJobRepository(),
                plans=SqlAlchemyDeploymentPlanRepository(),
                chains=SqlAlchemySketchChainRepository(),
                credentials=SqlAlchemyCredentialRepository(),
                lookup=_db_lease_lookup,
                handoff_auditor=selector_retirement.audit_pending_provider_keyed_bootstrap,
                credential_check=selector_retirement._credential_snapshot,
                state_root=sketch_state_root,
            )
            assert {row.chain_id for row in selector_boundary.chains} == {
                row.chain_id for row in retired_rows}
            assert all(row.status == "destroyed" for row in selector_boundary.chains)
            assert absent_catalog.paths == inventory_paths * 5
            assert destroy_commands == ["version", "init", "plan", "show"]
            assert apply_commands == ["show", "apply"]

        core_preview_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, core_preview_restart)), db.bind(core_preview_restart):
            # The real plan writer was directed to this disposable state root;
            # point the private core preview's fixed-root check to that same
            # root, without replacing its state seal or source validators.
            monkeypatch.setattr(core_destroy_preview, "DEFAULT_TERRAFORM_STATE_ROOT", state_root)
            core_state_path = Path(plan.evidence["terraformStatePath"])
            core_state_bytes = core_state_path.read_bytes()
            core_inventory = parse_applied_oci_core_state(
                core_state_bytes, proxy_count=plan.evidence["proxyCount"],
                elk_enabled=plan.evidence["elkEnabled"],
                compartment_id=plan.evidence["target"]["compartmentId"],
                engagement_name=engagement.name,
            )
            managed_prior = [{
                "address": row.address, "mode": "managed",
                "type": row.address.split(".", 1)[0],
                "provider_name": "registry.terraform.io/oracle/oci",
                "values": {"id": row.ocid},
            } for row in core_inventory.resources]
            data_prior = []
            for resource in json.loads(core_state_bytes)["resources"]:
                if resource["mode"] != "data":
                    continue
                for instance in resource["instances"]:
                    address = f'data.{resource["type"]}.{resource["name"]}'
                    if instance.get("index_key") == 0:
                        address += "[0]"
                    data_prior.append({
                        "address": address, "mode": "data", "type": resource["type"],
                        "provider_name": "registry.terraform.io/oracle/oci",
                        "values": {"id": instance["attributes"]["id"]},
                    })
            core_delete_changes = [{
                "address": row.address, "mode": "managed",
                "type": row.address.split(".", 1)[0],
                "provider_name": "registry.terraform.io/oracle/oci",
                "change": {"actions": ["delete"], "before": {"id": row.ocid},
                           "after": None, "after_unknown": {}},
            } for row in core_inventory.resources]
            core_destroy_shown = json.dumps({
                "applyable": True, "complete": True,
                "resource_changes": core_delete_changes,
                "prior_state": {"values": {"root_module": {
                    "resources": managed_prior + data_prior,
                }}},
            })
            core_preview_commands = []

            def core_preview_command(args, cwd, env):
                core_preview_commands.append(tuple(args))
                assert args[0] == "/usr/bin/terraform"
                assert cwd == Path(plan.evidence["runDirectory"])
                assert env["TF_DATA_DIR"] == plan.evidence["terraformDataDir"]
                if args[1] == "plan":
                    assert "-destroy" in args and "-detailed-exitcode" in args
                    output_path = Path(next(arg[5:] for arg in args if arg.startswith("-out=")))
                    assert output_path.is_file()
                    output_path.write_bytes(b"opaque reviewed OCI destroy plan fixture")
                    return subprocess.CompletedProcess(args, 2, "", "")
                assert args[1:3] == ["show", "-json"]
                return subprocess.CompletedProcess(args, 0, core_destroy_shown, "")

            core_destroy_plan = core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                command_runner=core_preview_command,
            )
            assert core_destroy_plan.status == "succeeded"
            assert len(core_destroy_plan.events) == 3
            assert core_destroy_plan.events[-1].message == "core destroy preview saved"
            assert core_destroy_plan.events[-1].data["resourceCount"] == len(core_inventory.resources)
            assert core_destroy_plan.events[-1].data["stateSha256"] == hashlib.sha256(core_state_bytes).hexdigest()
            core_destroy_plan_path = Path(core_destroy_plan.events[-1].data["planPath"])
            assert core_destroy_plan_path.is_file()
            assert core_destroy_plan.events[-1].data["planSha256"] == hashlib.sha256(
                core_destroy_plan_path.read_bytes(),
            ).hexdigest()
            assert [command[1] for command in core_preview_commands] == ["plan", "show"]
            assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
            assert SqlAlchemyJobRepository().get(job.id) == core_before
            assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
            assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        core_preview_read_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, core_preview_read_restart)), db.bind(core_preview_read_restart):
            assert SqlAlchemyJobRepository().get(core_destroy_plan.id) == core_destroy_plan
            with pytest.raises(core_destroy_preview.KeyedCoreDestroyPreviewAttention):
                core_destroy_preview.preview_pending_keyed_oci_core_destroy(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    command_runner=lambda *_args: pytest.fail("OCI destroy preview replayed"),
                )
            assert [command[1] for command in core_preview_commands] == ["plan", "show"]
            assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator

        core_apply_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, core_apply_restart)), db.bind(core_apply_restart):
            monkeypatch.setattr(core_destroy_apply, "DEFAULT_TERRAFORM_STATE_ROOT", state_root)
            monkeypatch.setattr(core_destroy_absence, "DEFAULT_TERRAFORM_STATE_ROOT", state_root)
            target = plan.evidence["target"]
            identity = {
                "id": "ocid1.instance.oc1..barraganapp",
                "compartmentId": target["compartmentId"],
                "canonicalRegionName": target["region"],
            }
            observed_oci = {}
            for resource in core_inventory.resources:
                kind, role = _OCI_ROLES[resource.address]
                observed_oci[resource.ocid] = {
                    "id": resource.ocid, "compartment-id": target["compartmentId"],
                    "freeform-tags": {
                        "barragan": "true", "barragan_engagement": engagement.name,
                        "barragan_environment": "barragan-testing",
                        "barragan_provider": "oci", "barragan_role": role,
                    },
                    "lifecycle-state": "RUNNING" if kind == "instance" else "AVAILABLE",
                }
            core_provider_absent = {"value": False}
            oci_calls = []
            cli = tmp_path / "simulated-oci-cli"
            cli.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            cli.chmod(0o700)

            def oci_read_command(argv, env):
                oci_calls.append(tuple(argv))
                assert argv[:8] == (
                    str(cli), "--auth", "instance_principal", "--region",
                    target["region"], "--output", "json", "--no-retry",
                )
                assert env["HOME"] == "/nonexistent"
                if argv[10] == "list":
                    kind = {
                        "dhcp-options": "dhcpoptions", "internet-gateway": "internetgateway",
                        "nat-gateway": "natgateway", "route-table": "routetable",
                        "security-list": "securitylist",
                    }.get(argv[9], argv[9])
                    rows = ([] if core_provider_absent["value"] else [
                        row for ocid, row in observed_oci.items()
                        if ocid.split(".")[1] == kind
                    ])
                    return subprocess.CompletedProcess(argv, 0, json.dumps({"data": rows}), "")
                assert argv[10] == "get" and argv[-1] in observed_oci
                if core_provider_absent["value"]:
                    return subprocess.CompletedProcess(
                        argv, 1, "", 'ServiceError: {"status":404,"code":"NotAuthorizedOrNotFound"}',
                    )
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps({"data": observed_oci[argv[-1]]}), "",
                )

            core_apply_commands = []

            def gated_core_destroy(args, *, scratch_path, intent_callback,
                                   started_callback, heartbeat_callback,
                                   result_callback, provider_keyed_v2, **_kwargs):
                assert args[0] == "/usr/bin/terraform" and args[1] in {"show", "apply"}
                assert provider_keyed_v2 is True
                assert scratch_path == Path(plan.evidence["runDirectory"])
                core_apply_commands.append(tuple(args))
                invocation = CommandIntent(
                    str(uuid4()), str(scratch_path),
                    hashlib.sha256(json.dumps(args, separators=(",", ":")).encode()).hexdigest(),
                )
                started = StartedCommand(invocation, ProcessIdentity(
                    str(uuid4()), 5000 + len(core_apply_commands),
                    5000 + len(core_apply_commands), 5000 + len(core_apply_commands),
                ))
                intent_callback(invocation)
                started_callback(started)
                heartbeat_callback(started)
                if args[1] == "apply":
                    assert any(argv[10] == "get" for argv in oci_calls)
                    core_provider_absent["value"] = True
                    applied_job = SqlAlchemyJobRepository().get(
                        f"job-provider-keyed-core-destroy-apply-{job.id.removeprefix('job-')}"
                    )
                    prestate = next(event.data for event in applied_job.events
                                    if event.message == "core destroy prestate identity fenced")
                    core_state_path.write_text(json.dumps({
                        "version": 4, "terraform_version": plan.evidence["terraformFingerprint"],
                        "lineage": prestate["lineage"], "serial": prestate["serial"] + 1,
                        "outputs": {}, "resources": [],
                    }), encoding="utf-8")
                output = core_destroy_shown if args[1] == "show" else ""
                result_callback(CommandAuditResult(started, 0, len(output), 0, False, False))
                return CommandResult(started, 0, output, "", False, False)

            def real_visibility_with_local_identity(observed, **options):
                return prove_oci_core_visibility(
                    observed, **options, identity_reader=lambda: dict(identity),
                )

            if apply_case != "worker_success_initial_dispatch_core_apply":
                applied_core_destroy = core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    gated_command_runner=gated_core_destroy,
                    visibility_prover=real_visibility_with_local_identity,
                    oci_command_runner=oci_read_command, oci_executable=cli,
                )
                assert applied_core_destroy.status == "succeeded"
                assert applied_core_destroy.events[-1].message == (
                    "core destroy applied; provider absence pending"
                )
                assert [args[1] for args in core_apply_commands] == ["show", "apply"]
                assert core_provider_absent["value"] is True
                pre_destroy_seal = next(event.data for event in applied_core_destroy.events
                                        if event.message == "core destroy prestate identity fenced")
                assert pre_destroy_seal["resourceIds"] == {
                    row.address: row.ocid for row in core_inventory.resources
                }
                assert pre_destroy_seal["preDestroyStateSha256"] == hashlib.sha256(core_state_bytes).hexdigest()
                empty_core_state = json.loads(core_state_path.read_text())
                assert empty_core_state["resources"] == [] and empty_core_state["outputs"] == {}
                assert empty_core_state["lineage"] == core_inventory.lineage
                assert empty_core_state["serial"] > core_inventory.serial
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
                assert SqlAlchemyJobRepository().get(job.id) == core_before
                assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
                assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
                assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        if apply_case != "worker_success_initial_dispatch_core_apply":
            core_apply_read_restart = db.configure(state.uri)
            with runtime_context(configure_runtime(runtime_settings, core_apply_read_restart)), db.bind(core_apply_read_restart):
                before_replay_oci_calls = len(oci_calls)
                with pytest.raises(core_destroy_apply.KeyedCoreDestroyApplyAttention):
                    core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                        reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                        gated_command_runner=lambda *_args, **_kwargs: pytest.fail(
                            "one-shot OCI core destroy replayed"
                        ),
                        oci_command_runner=oci_read_command, oci_executable=cli,
                    )
                assert len(oci_calls) == before_replay_oci_calls
                assert [args[1] for args in core_apply_commands] == ["show", "apply"]
                assert SqlAlchemyJobRepository().get(applied_core_destroy.id) == applied_core_destroy

        core_absence_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, core_absence_restart)), db.bind(core_absence_restart):
            before_absence_oci_calls = len(oci_calls)
            if apply_case not in {"worker_success_initial_dispatch_absence",
                                  "worker_success_initial_dispatch_core_apply"}:
                core_absent = core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    oci_command_runner=oci_read_command,
                    identity_reader=lambda: dict(identity),
                    max_scans=3, poll_seconds=0, pause=lambda _seconds: None,
                )
                assert core_absent.status == "succeeded"
                assert core_absent.action == "provider_keyed_core_destroy_absence"
                assert core_absent.events[-1].message == "core destroy exact absence proved"
                assert core_absent.events[-1].data["emptyStateSha256"] == hashlib.sha256(
                    core_state_path.read_bytes(),
                ).hexdigest()
                assert core_absent.events[-1].data["preDestroyResourceIdsSha256"] == (
                    pre_destroy_seal["resourceIdsSha256"]
                )
                witness = core_absent.events[-1].data["ociAbsenceWitness"]
                assert witness["phase"] == "absent"
                assert witness["auth"] == "instance_principal"
                assert witness["inventory_sha256"] == core_inventory.inventory_sha256
                assert witness["principal_sha256"] == pre_destroy_seal["ociVisibilityWitness"][
                    "principal_sha256"
                ]
                per_oci_scan = len({_OCI_ROLES[row.address][0] for row in core_inventory.resources}) + len(
                    core_inventory.resources,
                )
                assert len(oci_calls) - before_absence_oci_calls == per_oci_scan * 2
                assert all(call[10] in {"list", "get"} for call in oci_calls[before_absence_oci_calls:])
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
                assert SqlAlchemyJobRepository().get(job.id) == core_before
                assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
                assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before
                assert _db_lease_lookup(engagement.id) == (plan.id, "provider_keyed_teardown_fence")

        if apply_case not in {"worker_success_initial_dispatch_absence",
                                  "worker_success_initial_dispatch_core_apply"}:
            core_absence_read_restart = db.configure(state.uri)
            with runtime_context(configure_runtime(runtime_settings, core_absence_read_restart)), db.bind(core_absence_read_restart):
                before_saved_absence_reads = len(oci_calls)
                assert core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    oci_command_runner=oci_read_command,
                    identity_reader=lambda: dict(identity),
                    max_scans=3, poll_seconds=0, pause=lambda _seconds: pytest.fail("saved OCI absence slept"),
                ) == core_absent
                assert len(oci_calls) == before_saved_absence_reads
                assert [args[1] for args in core_apply_commands] == ["show", "apply"]

        inspector_negative_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, inspector_negative_restart)), db.bind(inspector_negative_restart):
            negative_targets = snapshot["publicVerificationTargets"]
            assert len(negative_targets) == len(core_ips)
            assert {row["host"] for row in negative_targets} == set(core_ips.values())
            assert all(row["type"] == "tcp-forbidden" and row["port"] == 22
                       for row in negative_targets)
            negative_probe_rounds = []

            class InspectorReadOnlyProbe:
                def run(self, *, host, ssh_key, spec):
                    assert host.provider == "linode" and host.resource_id == "12345"
                    assert ssh_key.private_key_path == str(inspector_key_path)
                    assert ssh_key.public_key.split()[:2] == inspector_public.split()[:2]
                    assert spec["strictNegativeTcp"] is True
                    assert spec["timeoutSeconds"] == 8
                    assert spec["negative"] == negative_targets
                    assert spec["positive"] == [{
                        "id": "inspector-external-control", "type": "tcp",
                        "host": "4.2.2.2", "port": 443,
                    }]
                    negative_probe_rounds.append(spec)
                    return {"ok": True, "results": [
                        {"id": "inspector-external-control", "type": "tcp",
                         "ok": True, "expected": "reachable", "observed": ""},
                        *[{"id": row["id"], "type": row["type"],
                           "ok": True, "expected": "closed",
                           "observed": {"status": "closed", "reason": "connection_refused"}}
                          for row in spec["negative"]],
                    ]}

            def fresh_do_absence(parent_job_id, **options):
                return reconcile_successful_digitalocean_destroy_absence(
                    parent_job_id, **options, transport=absent_catalog,
                    max_attempts=1, poll_interval_seconds=0,
                )

            def saved_oci_absence(parent_job_id, **options):
                return core_destroy_absence.prove_pending_keyed_oci_core_destroy_absence(
                    parent_job_id, **{**options,
                                      "identity_reader": lambda: dict(identity),
                                      "oci_command_runner": oci_read_command,
                                      "max_scans": 3, "poll_seconds": 0,
                                      "pause": lambda _seconds: None},
                )

            if apply_case not in {"worker_success_initial_dispatch_absence",
                                  "worker_success_initial_dispatch_core_apply"}:
                negative_proof = prove_pending_keyed_inspector_negative(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    runner=InspectorReadOnlyProbe(),
                    positive_control={"id": "inspector-external-control", "type": "tcp",
                                      "host": "4.2.2.2", "port": 443},
                    do_absence_reader=fresh_do_absence,
                    oci_absence_recognizer=saved_oci_absence,
                )
                assert negative_proof.status == "succeeded"
                assert negative_proof.input["ociAbsenceJobId"] == core_absent.id
                assert negative_proof.events[-1].message == "inspector exact public negative proved"
                assert len(negative_proof.events[-1].data["rounds"]) == 2
                assert len(negative_probe_rounds) == 2
                assert absent_catalog.paths == inventory_paths * 7
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
                assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
                assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before

        if apply_case not in {"worker_success_initial_dispatch_absence",
                                  "worker_success_initial_dispatch_core_apply"}:
            negative_read_restart = db.configure(state.uri)
            with runtime_context(configure_runtime(runtime_settings, negative_read_restart)), db.bind(negative_read_restart):
                class NoInspectorReplay:
                    def run(self, **_kwargs):
                        pytest.fail("saved Inspector negative proof replayed an external probe")

                assert prove_pending_keyed_inspector_negative(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    runner=NoInspectorReplay(),
                    positive_control={"id": "inspector-external-control", "type": "tcp",
                                      "host": "4.2.2.2", "port": 443},
                    do_absence_reader=fresh_do_absence,
                    oci_absence_recognizer=saved_oci_absence,
                ) == negative_proof
                assert len(negative_probe_rounds) == 2
                assert absent_catalog.paths == inventory_paths * 8
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator

        # The selected credential must see each scoped taggable type and firewall
        # before the one-shot DELETE. These are external responses only; the
        # source, provenance, fence, and saved-success readers remain real.
        class CompleteSelectorCatalog:
            def __init__(self):
                self.tag_present = True
                self.paths = []

            def request(self, origin, method, path, token):
                assert origin == selector_retirement._ORIGIN
                assert method == "GET" and token == "fixture-token"
                self.paths.append(path)
                if path.startswith("/databases?"):
                    raise PermissionError("database:read unavailable")
                if path == f"/tags/{intent.selector_tag}":
                    assert self.tag_present
                    return {"tag": {"name": intent.selector_tag,
                                    "resources": {"count": 0}}}
                endpoint = path.split("?", 1)[0]
                assert endpoint in {
                    "/droplets", "/images", "/volumes", "/snapshots",
                    "/firewalls", "/tags",
                }
                key = endpoint.removeprefix("/")
                if endpoint == "/snapshots":
                    assert path == "/snapshots?page=1&per_page=200&resource_type=volume"
                    return {"snapshots": None, "meta": {"total": 0}, "links": {}}
                if endpoint == "/tags":
                    assert not self.tag_present
                rows = []
                return {key: rows, "meta": {"total": 0}, "links": {"pages": {}}}

        class GuardedSelectorDelete:
            def __init__(self, catalog):
                self.catalog = catalog
                self.deletes = 0
                self.status_reads = 0

            def delete_tag(self, token, selector):
                assert token == "fixture-token" and selector == intent.selector_tag
                assert self.catalog.tag_present and self.deletes == 0
                self.deletes += 1
                self.catalog.tag_present = False
                return selector_retirement.DeleteResponse(204, b"")

            def get_tag_status(self, token, selector):
                assert token == "fixture-token" and selector == intent.selector_tag
                self.status_reads += 1
                return 404 if not self.catalog.tag_present else 200

        selector_catalog = CompleteSelectorCatalog()
        selector_delete = GuardedSelectorDelete(selector_catalog)
        selector_type_paths = [
            "/droplets?page=1&per_page=200",
            "/droplets?page=1&per_page=200&type=gpus",
            "/images?page=1&per_page=200&private=true",
            "/volumes?page=1&per_page=200",
            "/snapshots?page=1&per_page=200&resource_type=volume",
        ]
        if apply_case not in {"worker_success_initial_dispatch_absence",
                                  "worker_success_initial_dispatch_core_apply"}:
            selector_first_restart = db.configure(state.uri)
            with runtime_context(configure_runtime(runtime_settings, selector_first_restart)), db.bind(selector_first_restart):
                selector_child = selector_retirement.retire_pending_digitalocean_selector(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    core_absence_recognizer=saved_oci_absence,
                    catalog_transport=selector_catalog, delete_transport=selector_delete,
                )
                assert selector_child.status == "succeeded"
                assert [event.message for event in selector_child.events] == [
                    "selector retirement queued", "selector retirement started",
                    "selector DELETE intended", "selector DELETE 204 received",
                ]
                assert selector_child.input["selectorTag"] == intent.selector_tag
                assert selector_delete.deletes == 1
                assert selector_delete.status_reads == 0
                assert selector_catalog.paths == selector_type_paths + [
                    f"/tags/{intent.selector_tag}", "/firewalls?page=1&per_page=200",
                ]
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
                assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
                assert SqlAlchemyProviderResourceRepository().list_for_engagement(engagement.id) == records_before

            selector_read_restart = db.configure(state.uri)
            with runtime_context(configure_runtime(runtime_settings, selector_read_restart)), db.bind(selector_read_restart):
                paths_before_read = len(selector_catalog.paths)
                assert selector_retirement.recognize_pending_digitalocean_selector_retired(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    core_absence_recognizer=saved_oci_absence,
                    catalog_transport=selector_catalog, status_transport=selector_delete,
                ) == selector_child
                assert selector_delete.deletes == 1
                assert selector_delete.status_reads == 2
                assert selector_catalog.paths[paths_before_read:] == (
                    selector_type_paths + [
                        "/tags?page=1&per_page=200", "/firewalls?page=1&per_page=200",
                    ]
                ) * 2
                with pytest.raises(selector_retirement.SelectorRetirementAttention):
                    selector_retirement.retire_pending_digitalocean_selector(
                        reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                        core_absence_recognizer=saved_oci_absence,
                        catalog_transport=selector_catalog, delete_transport=selector_delete,
                    )
                assert selector_delete.deletes == 1
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator

        cleanup_preview_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, cleanup_preview_restart)), db.bind(cleanup_preview_restart):
            cleanup_gets = []

            class CleanupLinodeReads(RetainedLinodeReads):
                host_live = True
                firewall_live = True

                def request(self, method, path, token):
                    if path in {
                        "/linode/instances?page=1&page_size=100",
                        "/networking/firewalls?page=1&page_size=100",
                    }:
                        assert method == "GET" and token == "fixture-linode-token"
                        cleanup_gets.append(path)
                        visible = self.host_live if path.startswith("/linode") else self.firewall_live
                        identifier = 12345 if path.startswith("/linode") else 67890
                        rows = [{"id": identifier}] if visible else []
                        return {"data": rows, "page": 1,
                                "pages": 1, "results": len(rows)}
                    if path == "/networking/firewalls/67890/devices?page=1&page_size=100" and not self.host_live:
                        assert method == "GET" and token == "fixture-linode-token"
                        cleanup_gets.append(path)
                        return {"data": [], "page": 1, "pages": 1, "results": 0}
                    if ((path == "/linode/instances/12345" and not self.host_live)
                            or (path == "/networking/firewalls/67890" and not self.firewall_live)):
                        assert method == "GET" and token == "fixture-linode-token"
                        cleanup_gets.append(path)
                        try:
                            raise urllib.error.HTTPError(path, 404, "absent", {}, None)
                        except urllib.error.HTTPError as exc:
                            raise LinodeValidationError("external fixture 404") from exc
                    return super().request(method, path, token)

            def real_negative_saved(parent_id, **options):
                return prove_pending_keyed_inspector_negative(
                    parent_id, **options, do_absence_reader=fresh_do_absence,
                    oci_absence_recognizer=saved_oci_absence,
                    runner=InspectorReadOnlyProbe(),
                )

            cleanup_reader = CleanupLinodeReads()
            cleanup_preview = None
            if apply_case not in {"worker_success_initial_dispatch_absence",
                                  "worker_success_initial_dispatch_core_apply"}:
                cleanup_preview = linode_cleanup.preview_pending_linode_inspector_cleanup(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    transport=cleanup_reader, negative_recognizer=real_negative_saved,
                )
                assert cleanup_preview.origin == "retained"
                assert cleanup_preview.adoption_job_id == records_before[0].adoption_job_id
                assert cleanup_preview.host_record_id == "linode:inspector:12345"
                assert cleanup_preview.firewall_record_id == "linode:inspector-firewall:67890"
                assert cleanup_preview.credential_id == ready_child.events[4].data["credentialId"]
                assert cleanup_gets == [
                    "/linode/instances?page=1&page_size=100",
                    "/networking/firewalls?page=1&page_size=100",
                ]
                assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
                assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before

            class ExactLinodeDeletes:
                def __init__(self):
                    self.paths = []
                    self.lose_host_response = (
                        apply_case == "worker_success_initial_host_response_lost")

                def delete(self, path, token):
                    assert token == "fixture-linode-token"
                    assert path in {
                        "/linode/instances/12345", "/networking/firewalls/67890",
                    }
                    self.paths.append(path)
                    if path == "/linode/instances/12345":
                        assert len(self.paths) == 1 and cleanup_reader.host_live
                        cleanup_reader.host_live = False
                        if self.lose_host_response:
                            raise TimeoutError("external fixture lost host DELETE response")
                    else:
                        assert self.paths == [
                            "/linode/instances/12345", "/networking/firewalls/67890",
                        ] and cleanup_reader.firewall_live
                        cleanup_reader.firewall_live = False
                    return linode_cleanup.LinodeDeleteResponse(200, b"{}")

            cleanup_deleter = ExactLinodeDeletes()

            def saved_selector_with_oci(parent_id, **options):
                return selector_retirement.recognize_pending_digitalocean_selector_retired(
                    parent_id, **options, core_absence_recognizer=saved_oci_absence,
                )

            def retained_cleanup_preview(parent_id, **options):
                return linode_cleanup.preview_pending_linode_inspector_cleanup(
                    parent_id, **options, negative_recognizer=real_negative_saved,
                )

            def saved_selector_for_dispatch(parent_id, **options):
                return selector_retirement.recognize_pending_digitalocean_selector_retired(
                    parent_id, **options, core_absence_recognizer=saved_oci_absence,
                    catalog_transport=selector_catalog, status_transport=selector_delete,
                )

            def retire_selector_for_dispatch(parent_id, **options):
                return selector_retirement.retire_pending_digitalocean_selector(
                    parent_id, **options, core_absence_recognizer=saved_oci_absence,
                    catalog_transport=selector_catalog, delete_transport=selector_delete,
                )

            def run_real_cleanup(parent_id, **_options):
                assert parent_id == reviewed_parent.id
                return linode_cleanup.retire_pending_linode_inspector(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    read_transport=cleanup_reader, delete_transport=cleanup_deleter,
                    sleep=lambda _seconds: pytest.fail("fake Linode absence needed sleep"),
                    preview_reader=retained_cleanup_preview,
                    oci_reader=saved_oci_absence,
                    selector_reader=saved_selector_with_oci,
                    negative_reader=real_negative_saved,
                    selector_catalog_transport=selector_catalog,
                    selector_status_transport=selector_delete,
                )

            def no_replayed_one_shot(*_args, **_kwargs):
                pytest.fail("saved provider/core one-shot stage replayed")

            def apply_core_for_dispatch(parent_id, **options):
                nonlocal before_absence_oci_calls
                assert parent_id == reviewed_parent.id
                before_apply_visibility = len(oci_calls)
                applied = core_destroy_apply.apply_pending_keyed_oci_core_destroy(
                    parent_id, **options,
                    gated_command_runner=gated_core_destroy,
                    visibility_prover=real_visibility_with_local_identity,
                    oci_command_runner=oci_read_command, oci_executable=cli,
                )
                assert applied.status == "succeeded"
                assert any(call[10] == "get" for call in oci_calls[before_apply_visibility:])
                before_absence_oci_calls = len(oci_calls)
                return applied

            def run_private_dispatch():
                advance = (real_pending_advance
                           if apply_case == "worker_success_initial_dispatch_core_apply"
                           else pending_dispatch.advance_pending_keyed_terminal)
                return advance(
                    reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                    positive_control_ipv4="4.2.2.2",
                    preview_provider=no_replayed_one_shot,
                    preview_core=no_replayed_one_shot,
                    apply_core=(apply_core_for_dispatch
                                if apply_case == "worker_success_initial_dispatch_core_apply"
                                else no_replayed_one_shot),
                    prove_core_absence=saved_oci_absence,
                    prove_negative=real_negative_saved,
                    recognize_selector=saved_selector_for_dispatch,
                    retire_selector=(retire_selector_for_dispatch
                                     if apply_case in {"worker_success_initial_dispatch_absence",
                                 "worker_success_initial_dispatch_core_apply"}
                                     else no_replayed_one_shot),
                    retire_inspector=run_real_cleanup,
                )

            if apply_case == "worker_success_initial_host_response_lost":
                with pytest.raises(pending_dispatch.PendingKeyedDispatchAttention):
                    run_private_dispatch()
                assert cleanup_deleter.paths == ["/linode/instances/12345"]
                interrupted = SqlAlchemyJobRepository().get(
                    f"job-provider-keyed-inspector-linode-cleanup-{job.id.removeprefix('job-')}")
                assert interrupted.events[-1].message == "inspector host DELETE intended"
                assert SqlAlchemyJobRepository().get(reviewed_parent.id).status == "queued"
                assert _db_lease_lookup(engagement.id) == (
                    plan.id, "provider_keyed_teardown_fence")
                assert SqlAlchemyObserverSettingsRepository().get(engagement.id) == inspector_before
            else:
                if apply_case == "worker_success_initial_dispatch_core_apply":
                    assert core_apply_commands == []
                    assert core_provider_absent["value"] is False
                    assert core_state_path.read_bytes() == core_state_bytes
                    assert SqlAlchemyJobRepository().get(coordinator_id) == retired_coordinator
                linode_terminal = (scheduled_pending[0][0]()
                                   if apply_case == "worker_success_initial_dispatch_core_apply"
                                   else run_private_dispatch())

        if apply_case == "worker_success_initial_host_response_lost":
            linode_resume_restart = db.configure(state.uri)
            with runtime_context(configure_runtime(runtime_settings, linode_resume_restart)), db.bind(linode_resume_restart):
                linode_terminal = run_private_dispatch()

        terminal_assert_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, terminal_assert_restart)), db.bind(terminal_assert_restart):
            assert cleanup_deleter.paths == [
                "/linode/instances/12345", "/networking/firewalls/67890",
            ]
            assert linode_terminal.status == "succeeded"
            assert linode_terminal.input["origin"] == "retained"
            assert len(negative_probe_rounds) == 2
            assert linode_terminal.input["adoptionJobId"] == (
                cleanup_preview.adoption_job_id if cleanup_preview is not None
                else records_before[0].adoption_job_id
            )
            if apply_case in {"worker_success_initial_dispatch_absence",
                              "worker_success_initial_dispatch_core_apply"}:
                # These authentic branches enter after saved OCI apply or
                # saved preview, respectively, and run the remaining stages.
                assert selector_delete.deletes == 1
                assert selector_catalog.tag_present is False
                assert len(negative_probe_rounds) == 2
                absence_children = [row for row in SqlAlchemyJobRepository().list_for_engagement(engagement.id)
                                    if row.action == "provider_keyed_core_destroy_absence"]
                assert len(absence_children) == 1
                assert absence_children[0].status == "succeeded"
                assert absence_children[0].events[-1].message == "core destroy exact absence proved"
                per_oci_scan = len({_OCI_ROLES[row.address][0] for row in core_inventory.resources}) + len(
                    core_inventory.resources,
                )
                assert len(oci_calls) - before_absence_oci_calls == per_oci_scan * 2
                if apply_case == "worker_success_initial_dispatch_core_apply":
                    applied_core_destroy = SqlAlchemyJobRepository().get(
                        f"job-provider-keyed-core-destroy-apply-{job.id.removeprefix('job-')}"
                    )
                    assert applied_core_destroy.status == "succeeded"
                    assert applied_core_destroy.events[-1].message == (
                        "core destroy applied; provider absence pending"
                    )
                    assert [args[1] for args in core_apply_commands] == ["show", "apply"]
                    assert core_provider_absent["value"] is True
                    assert json.loads(core_state_path.read_text())["resources"] == []
                selector_child = SqlAlchemyJobRepository().get(
                    f"job-provider-keyed-selector-retirement-{job.id.removeprefix('job-')}")
                assert selector_child.status == "succeeded"
                assert selector_child.events[-1].message == "selector DELETE 204 received"
            assert linode_terminal.events[-1].message == "inspector local retirement committed"
            assert SqlAlchemyJobRepository().get(reviewed_parent.id).status == "succeeded"
            assert SqlAlchemyJobRepository().get(coordinator_id).status == "succeeded"
            assert _db_lease_lookup(engagement.id) is None

        linode_terminal_restart = db.configure(state.uri)
        with runtime_context(configure_runtime(runtime_settings, linode_terminal_restart)), db.bind(linode_terminal_restart):
            assert linode_cleanup.recognize_pending_linode_inspector_retired(
                reviewed_parent.id, environment="devtest",
            ) == linode_terminal
            before_replay_deletes = list(cleanup_deleter.paths)
            assert linode_cleanup.retire_pending_linode_inspector(
                reviewed_parent.id, environment="devtest", state_root=sketch_state_root,
                read_transport=cleanup_reader, delete_transport=cleanup_deleter,
            ) == linode_terminal
            if apply_case == "worker_success_initial_dispatch_core_apply":
                assert scheduled_pending[0][0]() == linode_terminal
                assert scheduled_pending[1][0]() == linode_terminal
                duplicate = app.test_client().post(route, json={
                    "confirmation": preview["confirmationPhrase"],
                    "snapshotId": preview["snapshotId"],
                })
                assert duplicate.status_code == 200
                assert duplicate.get_json()["job"]["id"] == reviewed_parent.id
                assert duplicate.get_json()["job"]["status"] == "succeeded"
                assert len(scheduled_pending) == 2
                assert pending_dispatch.recover_pending_keyed_dispatches(
                    environment="devtest", state_root=sketch_state_root,
                    positive_control_ipv4="4.2.2.2",
                    schedule=lambda *_args: pytest.fail("terminal parent rescheduled"),
                ) == []
            else:
                assert run_private_dispatch() == linode_terminal
            assert cleanup_deleter.paths == before_replay_deletes
