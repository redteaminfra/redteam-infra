# Copyright (c) 2026, Oracle and/or its affiliates.
import pytest
from dataclasses import replace

from app.domain import JobEvent
from app.services.engagement_operations import (
    CORE_DEPLOYMENT_ACTIONS,
    OperationsReadSnapshot,
    _capability_service_placements,
    _core_host,
    _latest_job_with_action,
    _latest_job_with_event_key,
    get_operations_overview,
    _inbound_channel,
    _merge_inspector_public_ingress,
    _mixed_interrupted_progress,
    _mixed_published_progress,
    _engagement_jobs,
    _mixed_initial_job_summary,
    _mark_stranded_pending_inbound_channels,
    _outbound_channel_rows,
    _sketch_row,
)
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from app.storage.engagement_repository import StoredEngagement
from app.storage.sketch_chain_repository import StoredSketchChain


def test_operations_projects_sketch_and_inbound_component_identity():
    sketch = _sketch_row({
        "chainId": "chain-1", "hostname": "edge-02", "role": "edge", "provider": "linode",
        "componentId": "edge-component-02", "edgeId": "edge-02",
    })
    channel = _inbound_channel({
        "channelId": "route-1", "chainId": "chain-1", "edge": "edge-02",
        "edgeComponentId": "edge-component-02", "middle": "middle-01",
        "middleComponentId": "middle-component",
    })
    assert sketch["componentId"] == "edge-component-02"
    assert sketch["edgeId"] == "edge-02"
    assert channel["edgeComponentId"] == "edge-component-02"
    assert channel["middleComponentId"] == "middle-component"


def _core_deployment_job(resource_names=None, *, action="pilot_standard_rti_guarded_execute", status="succeeded", proxy_count=2):
    return StoredJobRun(
        id="job-core", action=action, status=status,
        target="engagement:eng-test", target_type="engagement", target_id="eng-test",
        requested_by="operator",
        input={
            "engagementId": "eng-test", "engagementName": "original-name", "proxyCount": proxy_count,
            "resourceNames": resource_names or {
                "homebase": "homebase-original-name", "proxy01": "proxy01-original-name",
                "proxy02": "proxy02-original-name", "vcn": "barragan-original-name",
            },
        },
        artifact_refs=[], created_at="2026-09-11T12:00:00+00:00",
        started_at="2026-09-11T12:00:00+00:00", finished_at="2026-09-11T12:01:00+00:00", events=[],
    )


def test_mixed_initial_handoff_projection_tracks_only_current_core_and_plan():
    core = replace(_core_deployment_job(), input={
        **_core_deployment_job().input, "sketchStateSchema": "provider-keyed-v2",
        "corePlanId": "dpl-current"},
        events=[JobEvent(1, "info", "core ready", {"connectionDetails": []})])
    parent = replace(core, id="job-provider-keyed-mixed-initial-core",
                     action="provider_keyed_mixed_initial", status="running",
                     target="engagement:eng-test", target_type="engagement",
                     target_id="eng-test", finished_at=None,
                     input={"engagementId": "eng-test", "coreJobId": core.id,
                            "corePlanId": "dpl-current",
                            "phase": "awaiting_mixed_host_proof"})
    summary = _mixed_initial_job_summary([parent, core], core, core, None, "eng-test")
    assert summary == {"id": parent.id, "action": parent.action,
                       "status": "running", "createdAt": parent.created_at,
                       "finishedAt": None, "phase": "awaiting_mixed_host_proof"}
    engagement = StoredEngagement("eng-test", "opaque", "active", "operator",
                                  "small-dev-infra", "rev", {})
    snapshot = OperationsReadSnapshot(
        jobs={engagement.id: [parent, core]}, services={engagement.id: []},
        sketch_chains={engagement.id: []}, provider_records={engagement.id: []},
        all_provider_records=[], lifecycles={}, total_job_count=2,
        seed_job_exists=False)
    overview = get_operations_overview(
        engagement.id,
        type("Engagements", (), {"get": lambda _self, _id: engagement})(),
        type("Jobs", (), {"list_semantic_for_engagement":
            lambda _self, _id, recent_limit: [parent, core]})(),
        include_provider_findings=False, read_snapshot=snapshot)
    assert overview["mixedInitialJob"] == summary
    assert _mixed_initial_job_summary([parent, core], core, core, parent, "eng-test") is None
    newer = replace(core, id="job-new-core", input={**core.input, "corePlanId": "dpl-new"})
    assert _mixed_initial_job_summary([newer, parent, core], newer, newer, None, "eng-test") is None
    wrong = replace(parent, input={**parent.input, "corePlanId": "dpl-other"})
    assert _mixed_initial_job_summary([wrong, core], core, core, None, "eng-test") is None


@pytest.mark.parametrize("teardown_action", [
    "engagement_comprehensive_teardown",
    "provider_keyed_mixed_zero_apply_cleanup",
    "provider_keyed_mixed_interrupted_cleanup",
])
def test_mixed_initial_projection_ignores_completed_prior_generation_teardown(teardown_action):
    core = replace(_core_deployment_job(), created_at="2026-10-12T12:00:00+00:00",
                   input={**_core_deployment_job().input,
                          "sketchStateSchema": "provider-keyed-v2", "corePlanId": "dpl-current"},
                   events=[JobEvent(1, "info", "core ready", {"connectionDetails": []})])
    parent = replace(core, id="job-provider-keyed-mixed-initial-core",
                     action="provider_keyed_mixed_initial", status="running", finished_at=None,
                     events=[],
                     input={"engagementId": "eng-test", "coreJobId": core.id,
                            "corePlanId": "dpl-current", "phase": "awaiting_mixed_host_proof"})
    teardown = replace(core, id="job-old-teardown", action=teardown_action,
                       created_at="2026-10-11T12:00:00+00:00",
                       finished_at="2026-10-11T12:01:00+00:00")
    engagement = StoredEngagement("eng-test", "opaque", "active", "operator",
                                  "small-dev-infra", "rev", {})
    jobs = [parent, core, teardown]
    overview = get_operations_overview(
        engagement.id,
        type("Engagements", (), {"get": lambda _self, _id: engagement})(),
        type("Jobs", (), {"list_semantic_for_engagement":
            lambda _self, _id, recent_limit: jobs})(),
        include_provider_findings=False,
        read_snapshot=OperationsReadSnapshot(
            jobs={engagement.id: jobs}, services={engagement.id: []},
            sketch_chains={engagement.id: []}, provider_records={engagement.id: []},
            all_provider_records=[], lifecycles={}, total_job_count=3,
            seed_job_exists=False),
    )
    assert overview["mixedInitialJob"]["id"] == parent.id
    assert overview["teardownJob"] is None
    current_teardown = replace(teardown, created_at="2026-10-13T12:00:00+00:00",
                               finished_at="2026-10-13T12:01:00+00:00")
    jobs[:] = [current_teardown, parent, core]
    overview = get_operations_overview(
        engagement.id,
        type("Engagements", (), {"get": lambda _self, _id: engagement})(),
        type("Jobs", (), {"list_semantic_for_engagement":
            lambda _self, _id, recent_limit: jobs})(),
        include_provider_findings=False,
        read_snapshot=OperationsReadSnapshot(
            jobs={engagement.id: jobs}, services={engagement.id: []},
            sketch_chains={engagement.id: []}, provider_records={engagement.id: []},
            all_provider_records=[], lifecycles={}, total_job_count=3,
            seed_job_exists=False),
    )
    assert overview["mixedInitialJob"] is None
    assert overview["teardownJob"]["id"] == current_teardown.id


def test_mixed_initial_projection_reads_exact_parent_evicted_from_semantic_timeline(tmp_path):
    core = replace(_core_deployment_job(), input={**_core_deployment_job().input,
                   "sketchStateSchema": "provider-keyed-v2", "corePlanId": "dpl-current"},
                   events=[JobEvent(1, "info", "core ready", {"connectionDetails": []})])
    parent = replace(core, id="job-provider-keyed-mixed-initial-core",
                     action="provider_keyed_mixed_initial", status="running", finished_at=None,
                     events=[],
                     input={"engagementId": "eng-test", "coreJobId": core.id,
                            "corePlanId": "dpl-current", "phase": "awaiting_mixed_host_proof"})
    repository = SqliteJobRepository(tmp_path / "jobs.sqlite")
    repository.save(core)
    repository.save(parent)
    for index in range(251):
        repository.save(replace(
            core, id=f"job-noise-{index:03d}", action="unrelated_read", events=[],
            created_at=f"2026-09-12T{index // 60:02d}:{index % 60:02d}:00+00:00"))
    semantic = repository.list_semantic_for_engagement("eng-test", recent_limit=250)
    assert parent.id not in {row.id for row in semantic}
    summary = _mixed_initial_job_summary(semantic, core, core, None, "eng-test",
                                         job_repository=repository)
    assert summary["id"] == parent.id
    assert _mixed_initial_job_summary([core], core, core, core, "eng-test",
                                      job_repository=repository) is None


@pytest.mark.parametrize("order", [("linode", "digitalocean"),
                                    ("digitalocean", "linode")])
def test_interrupted_teardown_progress_tracks_children_and_no_plan(order):
    base = _core_deployment_job()
    parent = replace(
        base, id="job-provider-keyed-mixed-interrupted-cleanup-core",
        action="provider_keyed_mixed_interrupted_cleanup", status="queued",
        input={"coreJobId": "job-core", "phase": "plans_sealed",
               "source": {"ordered_providers": list(order), "scopes": [
                   {"provider": "digitalocean", "selector_retirement_pending": True}]}},
        finished_at=None,
    )
    worker = replace(base, id="job-provider-keyed-mixed-interrupted-plan-core",
                     action="provider_keyed_mixed_interrupted_plan_worker")
    second = replace(
        base, id=f"job-provider-keyed-mixed-interrupted-destroy-core-{order[1]}",
        action="provider_keyed_mixed_interrupted_destroy_apply", status="running",
        finished_at=None,
    )
    phase, progress = _mixed_interrupted_progress(parent, [worker, second])
    assert phase == f"{order[1]}_absence"
    assert progress == {"completed": 2, "total": 9}
    preview = replace(base, id="job-provider-keyed-mixed-core-destroy-preview-core",
                      action="provider_keyed_mixed_zero_apply_core_destroy_preview")
    phase, progress = _mixed_interrupted_progress(parent, [worker, second, preview])
    assert phase == "core_destroy_apply"
    assert progress == {"completed": 4, "total": 9}
    failed = replace(second, status="failed")
    assert _mixed_interrupted_progress(parent, [worker, failed])[0] == "attention"


@pytest.mark.parametrize("order", [("linode", "digitalocean"),
                                    ("digitalocean", "linode")])
def test_published_teardown_progress_tracks_both_provider_absences(order):
    base = _core_deployment_job()
    from teardown_progress_fixtures import initial_checkpoint
    core = replace(base, input={**base.input, "corePlanId": "plan-current"})
    parent = initial_checkpoint(core, order)
    parent = replace(parent, input={**parent.input, "phase": "plans_sealed"})
    first = replace(
        base, id=f"job-provider-keyed-mixed-published-destroy-core-{order[0]}",
        action="provider_keyed_mixed_published_destroy_apply",
        target_id="eng-test", status="succeeded", input={"cleanupParentId": parent.id, "coreJobId": "job-core"})
    second = replace(
        base, id=f"job-provider-keyed-mixed-published-destroy-core-{order[1]}",
        action="provider_keyed_mixed_published_destroy_apply",
        target_id="eng-test", status="running", finished_at=None, input={"cleanupParentId": parent.id, "coreJobId": "job-core"})
    assert _mixed_published_progress(parent, [first, second]) == (
        f"{order[1]}_absence", {"completed": 2, "total": 9})
    assert _mixed_published_progress(parent, [first, replace(second, status="failed")])[0] == "attention"
    marker = replace(
        base, id="job-provider-keyed-mixed-published-dispatch",
        action="provider_keyed_mixed_published_dispatch_claim",
        target_id="eng-test", status="running")
    class Repository:
        def list_for_engagement(self, _engagement_id):
            return [marker, parent]
    assert _engagement_jobs("eng-test", Repository()) == [parent]


def test_core_host_projects_semantic_identity_from_immutable_resource_names_after_rename():
    row = _core_host(
        {"displayName": "proxy02-original-name", "sshAlias": "proxy02-original-name", "role": "proxy"},
        _core_deployment_job(), "2026-09-11T12:01:00+00:00", "us-sanjose-1", {},
    )

    assert row["hostId"] == "proxy02"
    assert row["logicalName"] == "proxy02"
    assert row["expectedHostname"] == "proxy02-original-name"


@pytest.mark.parametrize("action,status", [
    ("infra_orientation_refresh", "succeeded"),
    ("pilot_standard_rti_guarded_execute", "failed"),
])
def test_core_host_rejects_unrelated_or_unsuccessful_connection_details_lineage(action, status):
    job = _core_deployment_job(action=action, status=status)
    row = _core_host(
        {"displayName": "proxy01-original-name", "sshAlias": "proxy01-original-name", "role": "proxy"},
        job, "2026-09-11T12:01:00+00:00", "us-sanjose-1", {},
    )

    assert "hostId" not in row


@pytest.mark.parametrize(
    "resource_names,proxy_count",
    [
        (None, True),
        ({"homebase": "homebase-x", "proxy01": True, "vcn": "barragan-x"}, 1),
        ({"homebase": "homebase-x", "proxy01": "homebase-x", "vcn": "barragan-x"}, 1),
        ({"homebase": "homebase-x", "proxy01": "proxy01-x.infra.redteam", "vcn": "barragan-x"}, 1),
        ({"homebase": "homebase-x", "proxy02": "proxy02-x", "vcn": "barragan-x"}, 1),
    ],
)
def test_core_host_rejects_malformed_resource_name_provenance(resource_names, proxy_count):
    job = _core_deployment_job(resource_names or {}, proxy_count=proxy_count)
    if resource_names is None:
        job.input["resourceNames"] = "not-a-map"
    row = _core_host(
        {"displayName": "proxy01-x", "sshAlias": "proxy01-x", "role": "proxy"},
        job, "2026-09-11T12:01:00+00:00", "us-sanjose-1", {},
    )

    assert "hostId" not in row


@pytest.mark.parametrize(
    "display_name,ssh_alias",
    [
        ("proxy01-original-nam", "proxy01-original-nam"),
        ("proxy03-original-name", "proxy03-original-name"),
        ("proxy01-other-name", "proxy01-other-name"),
        ("proxy01-original-name.infra.redteam", "proxy01-original-name.infra.redteam"),
        ("proxy01-original-name", "proxy01"),
    ],
)
def test_core_host_rejects_connection_details_not_exactly_joined_to_resource_name(display_name, ssh_alias):
    row = _core_host(
        {"displayName": display_name, "sshAlias": ssh_alias, "role": "proxy"},
        _core_deployment_job(), "2026-09-11T12:01:00+00:00", "us-sanjose-1", {},
    )

    assert "hostId" not in row


def test_overview_uses_successful_core_deploy_connections_when_newer_unrelated_job_has_details():
    deployment = replace(
        _core_deployment_job(),
        events=[JobEvent(1, "info", "deployed", {"connectionDetails": [
            {"role": "homebase", "displayName": "homebase-original-name", "sshAlias": "homebase-original-name"},
            {"role": "proxy", "displayName": "proxy01-original-name", "sshAlias": "proxy01-original-name"},
            {"role": "proxy", "displayName": "proxy02-original-name", "sshAlias": "proxy02-original-name"},
        ]})],
    )
    unrelated = replace(
        deployment, id="job-refresh", action="infra_orientation_refresh",
        events=[JobEvent(1, "info", "refresh", {"connectionDetails": [
            {"role": "proxy", "displayName": "proxy01-wrong", "sshAlias": "proxy01-wrong"},
        ]})],
    )
    teardown = replace(
        deployment, id="job-engagement-teardown-core", action="engagement_comprehensive_teardown",
        status="failed", created_at="2026-09-11T12:02:00+00:00", finished_at="2026-09-11T12:03:00+00:00",
        target="engagement:eng-test", target_type="engagement", target_id="eng-test",
        input={"engagementId": "eng-test", "coreJobId": "job-core", "scopeSnapshot": {
            "engagementId": "eng-test", "engagementName": "RENAMED", "coreJobId": "job-core",
            "snapshotId": "snapshot-1", "confirmationPhrase": "teardown-RENAMED", "chains": [],
            "ownedProviderRecordIds": [], "excludedUnmanagedProviderRecords": [],
            "core": {"jobId": "job-core", "workspace": "/tmp/core", "proxyCount": 2},
            "publicVerificationTargets": [],
            "inspector": {"tracked": False, "ownedProviderRecordIds": [], "recordOwners": {}, "verificationTargetCount": 0},
        }},
        events=[JobEvent(1, "error", "engagement teardown requires cleanup", {"finalCleanupStatus": "cleanup_not_verified"})],
    )
    engagement = StoredEngagement(
        id="eng-test", name="RENAMED", status="active", owner="operator", template_id="standard-rti",
        active_revision=None, input_parameters={},
    )

    class Engagements:
        def get(self, engagement_id):
            return engagement if engagement_id == engagement.id else None

    class Jobs:
        def list_semantic_for_engagement(self, engagement_id, recent_limit):
            return [unrelated, teardown, deployment]

    snapshot = OperationsReadSnapshot(
        jobs={"eng-test": [unrelated, teardown, deployment]}, services={"eng-test": []}, sketch_chains={"eng-test": []},
        provider_records={"eng-test": []}, all_provider_records=[], lifecycles={},
        total_job_count=3, seed_job_exists=False,
    )
    overview = get_operations_overview(
        "eng-test", Engagements(), Jobs(), include_provider_findings=False, read_snapshot=snapshot,
    )

    assert overview is not None
    assert [host["hostname"] for host in overview["coreInfrastructure"]] == [
        "homebase-original-name", "proxy01-original-name", "proxy02-original-name",
    ]
    assert [host["hostId"] for host in overview["coreInfrastructure"]] == ["homebase", "proxy01", "proxy02"]
    assert overview["activeJob"]["id"] == "job-refresh"
    assert overview["teardownJob"] == {
        "id": "job-engagement-teardown-core", "action": "engagement_comprehensive_teardown",
        "status": "failed", "createdAt": "2026-09-11T12:02:00+00:00", "finishedAt": "2026-09-11T12:03:00+00:00",
        "recoveryState": "recoverable",
    }


def test_inspector_snapshot_does_not_override_authoritative_inbound_channels():
    removed = _job(
        "job-remove",
        "inbound_channel_remove",
        [{"channelId": "channel-443", "status": "Removed"}],
    )
    stale_inspector = _job(
        "job-inspector",
        "inspector_inspection",
        [{"channelId": "channel-443", "status": "Validation Failed"}],
    )

    selected = _latest_job_with_event_key([stale_inspector, removed], "inboundChannels")

    assert selected is removed


@pytest.mark.parametrize("status", ["Removed", "Pending Apply", "Not Deployed"])
def test_inspector_evidence_does_not_change_removed_channel_status(monkeypatch, status):
    monkeypatch.setattr(
        "app.services.engagement_operations._latest_inspector_public_ingress_by_channel",
        lambda _engagement_id: {
            "channel-443": {
                "ok": False,
                "checkedAt": "2026-06-29T20:01:00+00:00",
                "detail": "stale failed probe",
            }
        },
    )

    channels = _merge_inspector_public_ingress(
        [{"channelId": "channel-443", "status": status, "validation": {"status": status}}],
        "eng-test",
    )

    assert channels[0]["status"] == status
    assert channels[0]["validation"]["status"] == status


def test_saved_channel_that_claimed_apply_started_without_job_is_blocked():
    channel = {
        "channelId": "udp-53",
        "status": "Pending Apply",
        "validation": {"detail": "Channel recorded and apply is starting."},
    }

    result = _mark_stranded_pending_inbound_channels([channel], [])

    assert result[0]["status"] == "Apply Blocked"
    assert result[0]["validation"]["status"] == "Apply Blocked"


def test_orientation_refresh_does_not_replace_core_deployment_boundary():
    deployment = _job("job-core", "pilot_standard_rti_guarded_execute", [])
    refresh = _job("job-refresh", "infra_orientation_refresh", [])

    selected = _latest_job_with_action([refresh, deployment], CORE_DEPLOYMENT_ACTIONS)

    assert selected is deployment


def test_successful_gosus_reconciliation_exposes_managed_inbound_service():
    job = StoredJobRun(
        id="job-gosus",
        action="engagement_capability_reconciliation",
        status="succeeded",
        target="engagement:eng-test",
        target_type="engagement",
        target_id="eng-test",
        requested_by="operator",
        input={
            "engagementId": "eng-test",
            "selectedRoles": {
                "homebase": [{"id": "go-simple-upload-server", "role": "go_simple_upload_server"}]
            },
        },
        artifact_refs=[],
        created_at="2026-06-29T20:00:00+00:00",
        started_at="2026-06-29T20:00:00+00:00",
        finished_at="2026-06-29T20:00:01+00:00",
        events=[],
    )

    assert _capability_service_placements([job]) == [
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


def test_failed_outbound_validation_survives_newer_orientation_refresh_for_durable_chain():
    deployment = _job("job-core", "pilot_standard_rti_guarded_execute", [])
    validation = StoredJobRun(
        **{
            **deployment.__dict__,
            "id": "job-validation",
            "action": "outbound_channel_validation",
            "status": "failed",
            "created_at": "2026-06-29T20:05:00+00:00",
            "input": {"engagementId": "eng-test", "channelId": "proxy01-sea-01"},
            "events": [
                JobEvent(
                    1,
                    "error",
                    "validation failed",
                    {
                        "outboundChannels": [
                            {
                                "channelId": "proxy01-sea-01",
                                "chainId": "proxy01-sea-01",
                                "proxy": "proxy01",
                                "edge": "edge-zy01",
                                "port": "3333",
                                "status": "Validation Failed",
                                "validation": {
                                    "status": "Validation Failed",
                                    "expectedPublicIp": "203.0.113.20",
                                },
                            }
                        ]
                    },
                )
            ],
        }
    )
    refresh = StoredJobRun(
        **{
            **deployment.__dict__,
            "id": "job-refresh",
            "action": "infra_orientation_refresh",
            "created_at": "2026-06-29T20:10:00+00:00",
            "events": [JobEvent(1, "info", "refresh", {"connectionDetails": []})],
        }
    )
    later_sibling_validation = StoredJobRun(
        **{
            **deployment.__dict__,
            "id": "job-later-sibling-validation",
            "action": "outbound_channel_validation",
            "created_at": "2026-06-29T20:09:00+00:00",
            "input": {"engagementId": "eng-test", "channelId": "proxy02-sea-01"},
            "events": [
                JobEvent(
                    1,
                    "info",
                    "sibling validation snapshot",
                    {
                        "outboundChannels": [
                            {
                                "channelId": "proxy01-sea-01",
                                "chainId": "proxy01-sea-01",
                                "proxy": "proxy01",
                                "edge": "edge-zy01",
                                "port": "3333",
                                "status": "Pending Proxy Configuration",
                            },
                            {
                                "channelId": "proxy02-sea-01",
                                "chainId": "proxy02-sea-01",
                                "proxy": "proxy02",
                                "edge": "edge-other",
                                "port": "3333",
                                "status": "Validated",
                            },
                        ]
                    },
                )
            ],
        }
    )
    chain = StoredSketchChain(
        chain_id="proxy01-sea-01",
        engagement_id="eng-test",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        status="deployed",
        burned=False,
        burned_note="",
        deploy_job_id="job-sketch",
        teardown_job_id="",
        terraform_working_directory="",
        nodes=[
            {"role": "middle", "hostname": "middle-zy01", "provider": "linode", "publicIp": "203.0.113.10"},
            {"role": "edge", "hostname": "edge-zy01", "provider": "linode", "publicIp": "203.0.113.20"},
        ],
        created_at="2026-06-29T20:01:00+00:00",
        updated_at="2026-06-29T20:02:00+00:00",
    )

    rows = _outbound_channel_rows(
        [refresh, later_sibling_validation, validation, deployment],
        later_sibling_validation,
        [chain],
        "zy01",
        _latest_job_with_action(
            [refresh, later_sibling_validation, validation, deployment],
            CORE_DEPLOYMENT_ACTIONS,
        ),
    )

    assert rows[0]["status"] == "Validation Failed"


def test_stale_outbound_status_does_not_override_replaced_durable_edge():
    deployment = _job("job-core", "pilot_standard_rti_guarded_execute", [])
    stale_apply = StoredJobRun(
        **{
            **deployment.__dict__,
            "id": "job-stale-apply",
            "action": "outbound_channel_apply",
            "created_at": "2026-06-29T20:05:00+00:00",
            "input": {"engagementId": "eng-test", "channelId": "proxy01-sea-01"},
            "events": [
                JobEvent(
                    1,
                    "info",
                    "old edge was ready",
                    {
                        "outboundChannels": [
                            {
                                "channelId": "proxy01-sea-01",
                                "chainId": "proxy01-sea-01",
                                "proxy": "proxy01",
                                "middle": "middle-zy01",
                                "edge": "edge-zy01",
                                "port": "3334",
                                "status": "Ready",
                                "validation": {"expectedPublicIp": "198.51.100.20"},
                            }
                        ]
                    },
                )
            ],
        }
    )
    chain = StoredSketchChain(
        chain_id="proxy01-sea-01",
        engagement_id="eng-test",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        status="deployed",
        burned=False,
        burned_note="",
        deploy_job_id="job-sketch",
        teardown_job_id="",
        terraform_working_directory="",
        nodes=[
            {"role": "middle", "hostname": "middle-zy01", "provider": "linode", "publicIp": "203.0.113.10"},
            {"role": "edge", "hostname": "edge-zy01", "provider": "linode", "publicIp": "203.0.113.20"},
        ],
        created_at="2026-06-29T20:01:00+00:00",
        updated_at="2026-06-29T20:06:00+00:00",
    )

    rows = _outbound_channel_rows(
        [stale_apply, deployment],
        stale_apply,
        [chain],
        "zy01",
        deployment,
    )

    assert rows[0]["status"] == "Pending Proxy Configuration"
    assert rows[0]["port"] == "3334"
    assert rows[0]["validation"]["expectedPublicIp"] == "203.0.113.20"
    assert rows[0]["middle"] == "middle-zy01"
    assert rows[0]["edge"] == "edge-zy01"


def _job(job_id: str, action: str, inbound_channels: list[dict[str, str]]) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action=action,
        status="succeeded",
        target="engagement:eng-test",
        target_type="engagement",
        target_id="eng-test",
        requested_by="operator",
        input={"engagementId": "eng-test"},
        artifact_refs=[],
        created_at="2026-06-29T20:00:00+00:00",
        started_at="2026-06-29T20:00:00+00:00",
        finished_at="2026-06-29T20:00:01+00:00",
        events=[JobEvent(1, "info", "snapshot", {"inboundChannels": inbound_channels})],
    )


@pytest.mark.parametrize("status", ["Pending Apply", "Not Deployed"])
def test_retired_channel_desired_state_is_not_projected_as_live_service_failure(status):
    from types import SimpleNamespace
    from app.services.engagement_operations import _merge_service_readiness
    channel = {"channelId": "channel-six", "serviceId": "site-six", "status": status,
        "validation": {"status": status, "externalIngressVerified": False}}
    assert _merge_service_readiness([channel], [SimpleNamespace(service_id="site-six",
        name="Desired", status="Removed")]) == [channel]
