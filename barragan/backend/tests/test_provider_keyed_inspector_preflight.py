# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted-only Inspector identity proof for the keyed teardown handoff."""

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.domain import JobEvent
from app.services import engagement_teardown as teardown
from app.services import provider_keyed_comprehensive_teardown as coordinator
from app.services import provider_keyed_inspector_preflight as service
from app.storage.observer_settings_repository import StoredObserverSettings
from app.storage.provider_resource_repository import StoredProviderResourceRecord
from test_provider_keyed_comprehensive_teardown import _options


class Settings:
    def __init__(self, value):
        self.value = value

    def get(self, engagement_id):
        return self.value if self.value.engagement_id == engagement_id else None

    def save(self, _value):
        pytest.fail("read-only Inspector gate saved settings")


class Resources:
    def __init__(self, rows):
        self.rows = list(rows)
        self.reads = 0

    def list_for_engagement(self, engagement_id):
        self.reads += 1
        return [row for row in self.rows if row.engagement_id == engagement_id]

    def save(self, _value):
        pytest.fail("read-only Inspector gate saved a resource")


def _case(tmp_path, *, retired_target=False):
    jobs, queued, scope, plans, _clock, options = _options(tmp_path)
    if retired_target:
        snapshot = {**queued.input["scopeSnapshot"], "publicVerificationTargets": [
            {"id": "retired-endpoint", "type": "tcp-forbidden", "host": "203.0.113.25", "port": 443}]}
        snapshot["inspector"] = {**snapshot["inspector"], "verificationTargetCount": 1}
        snapshot["snapshotId"] = teardown._fingerprint({
            key: value for key, value in snapshot.items() if key != "snapshotId"})
        queued = jobs.save(replace(
            queued, input={**queued.input, "scopeSnapshot": snapshot},
            events=[JobEvent(1, "info", "engagement teardown queued",
                             {"snapshotId": snapshot["snapshotId"]})],
        ))
    child = coordinator.run_provider_keyed_comprehensive_handoff(queued.id, **options)
    assert child.input["phase"] == "awaiting_inspector_preflight"
    host = {
        "provider": "linode", "resourceType": "instance", "resourceId": "987654",
        "name": "opaque-inspector", "region": "us-east", "publicIp": "203.0.113.25",
        "sshUser": "barragan", "status": "running",
        "metadata": {
            "adminIdentityVersion": 1, "rootLoginDisabled": True,
            "supportPreparationVersion": 1, "supportPreparedPackages": ["nmap"],
        },
    }
    stamp = datetime(2026, 10, 8, tzinfo=timezone.utc).isoformat()
    settings = Settings(StoredObserverSettings(
        engagement_id=queued.target_id, enabled=True, provider="linode",
        region="us-east", size="g6-nanode-1", mode="continuous",
        schedule_weekdays=[], schedule_time_utc="00:00", check_families=[],
        forbidden_tcp_ports=[], port_scan_profiles=[], current_host=host,
        idle_retention_until="", last_scheduled_slot="", last_mutation_job_inspected="",
        created_at=stamp, updated_at=stamp,
    ))
    record = StoredProviderResourceRecord(
        id="linode:inspector:987654", engagement_id=queued.target_id,
        engagement_name="opaque", provider="linode", resource_type="inspector_instance",
        resource_id="987654", name="opaque-inspector", region="us-east",
        lifecycle_state="active", status="active", source="barragan_inspector_job",
        metadata={"barraganOwned": True, "role": "inspector",
                  "inspectionJobId": "job-original-inspector",
                  "publicIp": "203.0.113.25", "publicIps": ["203.0.113.25"]},
        adoption_job_id="job-original-inspector", adopted_at=stamp, updated_at=stamp,
    )
    resources = Resources([record])
    gate_options = dict(
        environment="devtest", job_repository=jobs, plan_repository=plans,
        lease_lookup=options["lease_lookup"], settings_repository=settings,
        provider_resource_repository=resources,
    )
    return jobs, queued, scope, plans, child, settings, resources, record, gate_options


def _configured_firewall(settings, resources, record, *, child_present=True):
    firewall = {"provider": "linode", "resourceType": "firewall", "resourceId": "fw-1",
                "name": "opaque-firewall", "managementSourceCidr": "203.0.113.10/32"}
    settings.value = replace(settings.value, current_host={
        **settings.value.current_host,
        "metadata": {**settings.value.current_host["metadata"], "providerFirewall": firewall},
    })
    resources.rows[0] = replace(record, metadata={**record.metadata, "providerFirewall": firewall})
    if child_present:
        resources.rows.append(replace(
            record, id="linode:inspector-firewall:fw-1", resource_type="inspector_firewall",
            resource_id="fw-1", name="opaque-firewall",
            metadata={"barraganOwned": True, "role": "inspector_firewall",
                      "inspectorHostResourceId": record.resource_id,
                      "inspectionJobId": record.adoption_job_id,
                      "managementSourceCidr": "203.0.113.10/32"},
        ))


def test_unique_explicitly_owned_prepared_inspector_is_read_only_evidence(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    prior_jobs, prior_settings, prior_records = jobs.list(), settings.value, list(resources.rows)
    evidence = service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert evidence.coordinator_job_id == child.id
    assert evidence.owned_record_id == record.id
    assert evidence.provider_resource_id == record.resource_id
    assert evidence.prepared_metadata_only and not evidence.live_reachability_proven
    assert jobs.list() == prior_jobs and settings.value == prior_settings
    assert resources.rows == prior_records and resources.reads == 2
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")


def test_linode_persisted_offline_status_retains_exact_owned_read_only_gate(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    settings.value = replace(settings.value, current_host={
        **settings.value.current_host, "status": "offline",
    })
    prior_jobs, prior_settings, prior_records = jobs.list(), settings.value, list(resources.rows)
    evidence = service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert evidence.owned_record_id == record.id
    assert evidence.prepared_metadata_only and not evidence.live_reachability_proven
    assert jobs.list() == prior_jobs and settings.value == prior_settings
    assert resources.rows == prior_records and resources.reads == 2
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")

    resources.rows[0] = replace(record, metadata={**record.metadata, "barraganOwned": False})
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)


@pytest.mark.parametrize("provider,status", [
    ("digitalocean", "offline"),
    ("linode", "stopped"),
])
def test_persisted_offline_exception_does_not_broaden_provider_or_status(
    tmp_path, provider, status,
):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    settings.value = replace(settings.value, provider=provider, current_host={
        **settings.value.current_host, "provider": provider, "status": status,
    })
    with pytest.raises(service.ProviderKeyedInspectorPreflightRequired):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert resources.reads == 0


def test_exact_owned_firewall_child_is_required_when_settings_name_it(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    _configured_firewall(settings, resources, record, child_present=False)
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    _configured_firewall(settings, resources, record)
    assert service.inspect_prepared_keyed_teardown_inspector(
        queued.id, **options).owned_record_id == record.id


def test_host_record_firewall_manifest_cannot_disagree_with_settings(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    _configured_firewall(settings, resources, record)
    host_record = resources.rows[0]
    resources.rows[0] = replace(host_record, metadata={
        **host_record.metadata,
        "providerFirewall": {**host_record.metadata["providerFirewall"],
                             "resourceId": "other-firewall"},
    })
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)


@pytest.mark.parametrize("drift", ["id", "source", "owner", "host", "job", "extra"])
def test_firewall_child_must_have_exact_owned_identity(tmp_path, drift):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    _configured_firewall(settings, resources, record)
    firewall_record = resources.rows[1]
    if drift == "id":
        resources.rows[1] = replace(firewall_record, id="other")
    elif drift == "source":
        resources.rows[1] = replace(firewall_record, source="manual")
    elif drift == "owner":
        resources.rows[1] = replace(firewall_record, metadata={
            **firewall_record.metadata, "barraganOwned": False})
    elif drift == "host":
        resources.rows[1] = replace(firewall_record, metadata={
            **firewall_record.metadata, "inspectorHostResourceId": "other"})
    elif drift == "job":
        resources.rows[1] = replace(firewall_record, adoption_job_id="other-job")
    else:
        resources.rows.append(replace(firewall_record, id="extra-firewall", resource_id="fw-2"))
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)


@pytest.mark.parametrize("drift, error", [
    ("no_settings", service.ProviderKeyedInspectorPreflightRequired),
    ("no_record", service.ProviderKeyedInspectorPreflightRequired),
    ("ambiguous", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("wrong_owner", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("wrong_record_id", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("wrong_job_id", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("wrong_firewall_host", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("terminal", service.ProviderKeyedInspectorPreflightRequired),
    ("settings_id", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("settings_ip", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("settings_region", service.ProviderKeyedInspectorPreflightAmbiguous),
    ("unprepared", service.ProviderKeyedInspectorPreflightRequired),
    ("parent", service.ProviderKeyedInspectorPreflightError),
    ("lease", service.ProviderKeyedInspectorPreflightError),
])
def test_absent_ambiguous_or_stale_identity_fails_without_writes(tmp_path, drift, error):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    if drift == "no_settings":
        settings.value = replace(settings.value, engagement_id="other")
    elif drift == "no_record":
        resources.rows = []
    elif drift == "ambiguous":
        resources.rows.append(replace(record, id="other", resource_id="111"))
    elif drift == "wrong_owner":
        resources.rows[0] = replace(record, metadata={**record.metadata, "barraganOwned": False})
    elif drift == "wrong_record_id":
        resources.rows[0] = replace(record, id="unrelated-id")
    elif drift == "wrong_job_id":
        resources.rows[0] = replace(record, metadata={**record.metadata, "inspectionJobId": "other-job"})
    elif drift == "wrong_firewall_host":
        resources.rows.append(replace(
            record, id="linode:inspector-firewall:fw-1", resource_type="inspector_firewall",
            resource_id="fw-1", metadata={"barraganOwned": True,
                                          "inspectorHostResourceId": "other-host"}))
    elif drift == "terminal":
        resources.rows[0] = replace(record, status="destroyed", lifecycle_state="destroyed")
    elif drift == "settings_id":
        settings.value = replace(settings.value, current_host={
            **settings.value.current_host, "resourceId": "other"})
    elif drift == "settings_ip":
        settings.value = replace(settings.value, current_host={
            **settings.value.current_host, "publicIp": "203.0.113.50"})
    elif drift == "settings_region":
        settings.value = replace(settings.value, current_host={
            **settings.value.current_host, "region": "us-west"})
    elif drift == "unprepared":
        settings.value = replace(settings.value, current_host={
            **settings.value.current_host, "metadata": {}})
    elif drift == "parent":
        jobs.save(replace(queued, input={**queued.input, "phase": "attention"}))
    else:
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")
    before = jobs.list()
    with pytest.raises(error):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert jobs.list() == before and resources.reads <= 1


def test_retired_target_collision_fails_before_outbound(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(
        tmp_path, retired_target=True)
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert resources.reads == 0


def test_record_change_during_read_fails_final_authority_reread(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    original = resources.list_for_engagement
    def changing(engagement_id):
        result = original(engagement_id)
        if resources.reads == 1:
            resources.rows[0] = replace(record, resource_id="changed")
        return result
    resources.list_for_engagement = changing
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert resources.reads == 2


def test_settings_change_during_read_fails_final_authority_reread(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, record, options = _case(tmp_path)
    original = settings.get
    reads = 0
    def changing(engagement_id):
        nonlocal reads
        reads += 1
        if reads == 2:
            settings.value = replace(settings.value, updated_at="changed")
        return original(engagement_id)
    settings.get = changing
    with pytest.raises(service.ProviderKeyedInspectorPreflightAmbiguous):
        service.inspect_prepared_keyed_teardown_inspector(queued.id, **options)
    assert reads == 2
