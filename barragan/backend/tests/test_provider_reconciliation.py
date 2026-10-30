# Copyright (c) 2026, Oracle and/or its affiliates.
import subprocess
from types import SimpleNamespace

from app.domain import JobEvent
from app.services import provider_reconciliation
from app.storage.engagement_repository import StoredEngagement
from app.storage.job_repository import StoredJobRun


def test_live_discovery_is_opt_in_by_default(monkeypatch):
    provider_reconciliation.clear_provider_discovery_cache()
    monkeypatch.delenv(provider_reconciliation.LIVE_DISCOVERY_ENV, raising=False)

    assert provider_reconciliation.discover_provider_resources() == []


def test_live_discovery_uses_short_ttl_cache(monkeypatch):
    provider_reconciliation.clear_provider_discovery_cache()
    calls = []
    monkeypatch.setenv(provider_reconciliation.LIVE_DISCOVERY_ENV, "true")
    monkeypatch.setenv(provider_reconciliation.LIVE_DISCOVERY_CACHE_SECONDS_ENV, "60")

    def oci_resources():
        calls.append("oci")
        return [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..cached",
                "name": "homebase-cache01",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "metadata": {"barraganOwned": True},
            }
        ]

    monkeypatch.setattr(provider_reconciliation, "_discover_oci_resources", oci_resources)
    monkeypatch.setattr(provider_reconciliation, "_discover_linode_resources", lambda: [])
    monkeypatch.setattr(provider_reconciliation, "_discover_digitalocean_resources", lambda: [])

    first = provider_reconciliation.discover_provider_resources()
    first[0]["name"] = "mutated-by-caller"
    second = provider_reconciliation.discover_provider_resources()

    assert calls == ["oci"]
    assert second[0]["name"] == "homebase-cache01"


def test_live_discovery_cache_can_be_disabled(monkeypatch):
    provider_reconciliation.clear_provider_discovery_cache()
    calls = []
    monkeypatch.setenv(provider_reconciliation.LIVE_DISCOVERY_ENV, "true")
    monkeypatch.setenv(provider_reconciliation.LIVE_DISCOVERY_CACHE_SECONDS_ENV, "0")
    monkeypatch.setattr(
        provider_reconciliation,
        "_discover_oci_resources",
        lambda: calls.append("oci") or [],
    )
    monkeypatch.setattr(provider_reconciliation, "_discover_linode_resources", lambda: [])
    monkeypatch.setattr(provider_reconciliation, "_discover_digitalocean_resources", lambda: [])

    provider_reconciliation.discover_provider_resources()
    provider_reconciliation.discover_provider_resources()

    assert calls == ["oci", "oci"]


def test_reconciliation_flags_name_matched_resource_for_existing_engagement():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [_engagement("eng-or03", "OR03")],
        [],
        [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.or03",
                "name": "homebase-or03",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "metadata": {},
            }
        ],
    )

    assert len(reconciliation.orphan_candidates) == 1
    candidate = reconciliation.orphan_candidates[0]
    assert candidate["engagementId"] == "eng-or03"
    assert candidate["name"] == "homebase-or03"
    assert candidate["classification"] == "unmanaged_rti"
    assert candidate["actions"] == ["track", "mark_destroyed"]
    assert "does not carry Barragan ownership tags" in candidate["reason"]


def test_reconciliation_skips_unknown_untagged_lookalikes_to_avoid_false_positive():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [],
        [],
        [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.of03",
                "name": "homebase-of03-prod",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "metadata": {},
            }
        ],
    )

    assert reconciliation.provider_resource_count == 1
    assert reconciliation.orphan_candidates == []


def test_reconciliation_surfaces_tagged_resource_without_local_engagement():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [],
        [],
        [
            {
                "provider": "linode",
                "resourceType": "instance",
                "resourceId": "12345",
                "name": "edge-ff10-us-sea-01",
                "region": "us-sea",
                "lifecycleState": "running",
                "engagementName": "FF10",
                "metadata": {"barraganOwned": True, "tags": ["FF10", "barragan"]},
            }
        ],
    )

    assert len(reconciliation.orphan_candidates) == 1
    candidate = reconciliation.orphan_candidates[0]
    assert candidate["engagementId"] == ""
    assert candidate["engagementName"] == "FF10"
    assert candidate["classification"] == "barragan_orphan"
    assert candidate["actions"] == ["track", "mark_destroyed", "tear_down"]


def test_reconciliation_surfaces_unrecorded_resource_inside_active_engagement():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [_engagement("eng-or08", "OR08")],
        [
            _job(
                "job-or08-core",
                "pilot_standard_rti_guarded_execute",
                "succeeded",
                "eng-or08",
                [
                    JobEvent(
                        1,
                        "info",
                        "pilot Standard RTI run finished",
                        {
                            "connectionDetails": [
                                {
                                    "displayName": "homebase-or08",
                                    "role": "homebase",
                                    "region": "us-sanjose-1",
                                }
                            ],
                            "mutationStatus": "deployed",
                            "finalCleanupStatus": "pending_operator_teardown",
                        },
                    )
                ],
            )
        ],
        [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.homebase",
                "name": "homebase-or08",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementName": "OR08",
                "metadata": {},
            },
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.proxy01",
                "name": "proxy01-or08",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementName": "OR08",
                "metadata": {},
            },
        ],
    )

    assert [candidate["name"] for candidate in reconciliation.orphan_candidates] == ["proxy01-or08"]


def test_reconciliation_matches_active_sketch_resources_by_provider_id():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [_engagement("eng-or09", "OR09")],
        [
            _job(
                "job-or09-sketch",
                "linode_sketch_deploy",
                "succeeded",
                "eng-or09",
                [
                    JobEvent(
                        1,
                        "info",
                        "terraform output recorded",
                        {
                            "sketchInfrastructure": [
                                {
                                    "chainId": "proxy01-sea-01",
                                    "hostname": "edge-or09-us-sea-proxy01-sea-01",
                                    "provider": "linode",
                                    "providerInstanceId": "12345",
                                    "role": "edge",
                                    "publicIp": "203.0.113.10",
                                    "region": "us-sea",
                                    "status": "deployed",
                                }
                            ]
                        },
                    )
                ],
            )
        ],
        [
            {
                "provider": "linode",
                "resourceType": "instance",
                "resourceId": "12345",
                "name": "edge-or09-us-sea-proxy01-sea-01",
                "region": "us-sea",
                "lifecycleState": "running",
                "engagementName": "OR09",
                "metadata": {"barraganOwned": True, "publicIps": ["203.0.113.10"]},
            },
            {
                "provider": "linode",
                "resourceType": "instance",
                "resourceId": "67890",
                "name": "edge-or09-us-sea-proxy02-sea-01",
                "region": "us-sea",
                "lifecycleState": "running",
                "engagementName": "OR09",
                "metadata": {"barraganOwned": True, "publicIps": ["203.0.113.20"]},
            },
        ],
    )

    assert [candidate["resourceId"] for candidate in reconciliation.orphan_candidates] == ["67890"]


def test_reconciliation_keeps_engagement_fallback_for_active_jobs_without_resource_rows():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [_engagement("eng-or10", "OR10")],
        [
            _job(
                "job-or10-core",
                "pilot_standard_rti_guarded_execute",
                "running",
                "eng-or10",
                [JobEvent(1, "info", "terraform apply started", {"phase": "apply"})],
            )
        ],
        [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.or10",
                "name": "homebase-or10",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementName": "OR10",
                "metadata": {},
            }
        ],
    )

    assert reconciliation.orphan_candidates == []


def test_reconciliation_does_not_fallback_for_succeeded_jobs_without_resource_rows():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [_engagement("eng-or11", "OR11")],
        [
            _job(
                "job-or11-core",
                "pilot_standard_rti_guarded_execute",
                "succeeded",
                "eng-or11",
                [
                    JobEvent(
                        1,
                        "info",
                        "pilot Standard RTI run finished without usable resource identity",
                        {"mutationStatus": "deployed", "finalCleanupStatus": "pending_operator_teardown"},
                    )
                ],
            )
        ],
        [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.or11",
                "name": "homebase-or11",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementName": "OR11",
                "metadata": {},
            }
        ],
    )

    assert [candidate["name"] for candidate in reconciliation.orphan_candidates] == ["homebase-or11"]


def test_reconciliation_matches_active_tracked_provider_records():
    reconciliation = provider_reconciliation.reconcile_provider_inventory(
        [_engagement("eng-or12", "OR12")],
        [],
        [
            {
                "provider": "digitalocean",
                "resourceType": "droplet",
                "resourceId": "67890",
                "name": "edge-or12-sfo3-proxy02-sfo3-01",
                "region": "sfo3",
                "lifecycleState": "active",
                "engagementName": "OR12",
                "metadata": {"barraganOwned": True, "publicIps": ["198.51.100.25"]},
            }
        ],
        [
            {
                "provider": "digitalocean",
                "resourceType": "droplet",
                "resourceId": "67890",
                "name": "edge-or12-sfo3-proxy02-sfo3-01",
                "region": "sfo3",
                "lifecycleState": "active",
                "engagementId": "eng-or12",
                "engagementName": "OR12",
                "metadata": {"barraganOwned": True, "publicIps": ["198.51.100.25"]},
            }
        ],
    )

    assert reconciliation.orphan_candidates == []


def test_linode_resource_mapping_uses_read_only_instance_inventory_shape():
    rows = provider_reconciliation._linode_resources_from_response(
        {
            "data": [
                {
                    "id": 12345,
                    "label": "middle01-FF10",
                    "region": "us-sea",
                    "status": "running",
                    "tags": ["FF10", "barragan", "barragan-testing"],
                    "ipv4": ["203.0.113.10"],
                },
                {"id": 99999, "label": "personal-vm", "region": "us-sea", "status": "running", "tags": []},
            ]
        }
    )

    assert len(rows) == 1
    assert rows[0]["provider"] == "linode"
    assert rows[0]["resourceType"] == "instance"
    assert rows[0]["resourceId"] == "12345"
    assert rows[0]["engagementName"] == "FF10"
    assert rows[0]["metadata"]["barraganOwned"] is True
    assert rows[0]["metadata"]["publicIps"] == ["203.0.113.10"]


def test_digitalocean_resource_mapping_uses_read_only_droplet_inventory_shape():
    rows = provider_reconciliation._digitalocean_resources_from_response(
        {
            "droplets": [
                {
                    "id": 67890,
                    "name": "edge-FF10-sfo3-01",
                    "region": {"slug": "sfo3"},
                    "status": "active",
                    "tags": ["FF10", "barragan"],
                    "networks": {
                        "v4": [
                            {"type": "public", "ip_address": "198.51.100.25"},
                            {"type": "private", "ip_address": "10.0.0.2"},
                        ]
                    },
                }
            ]
        }
    )

    assert len(rows) == 1
    assert rows[0]["provider"] == "digitalocean"
    assert rows[0]["resourceType"] == "droplet"
    assert rows[0]["resourceId"] == "67890"
    assert rows[0]["region"] == "sfo3"
    assert rows[0]["metadata"]["publicIps"] == ["198.51.100.25"]


def test_oci_resource_mapping_uses_tags_and_current_region():
    rows = provider_reconciliation._oci_resources_from_response(
        "compute_instance",
        {
            "data": [
                {
                    "id": "ocid1.instance.oc1..abc",
                    "display-name": "homebase-ff10",
                    "lifecycle-state": "RUNNING",
                    "freeform-tags": {
                        "barragan": "true",
                        "barragan_engagement": "FF10",
                        "barragan_engagement_id": "eng-ff10",
                    },
                    "compartment-id": "ocid1.compartment.oc1..testing",
                }
            ]
        },
        "us-sanjose-1",
    )

    assert rows[0]["provider"] == "oci"
    assert rows[0]["resourceType"] == "compute_instance"
    assert rows[0]["engagementId"] == "eng-ff10"
    assert rows[0]["engagementName"] == "FF10"
    assert rows[0]["metadata"]["barraganOwned"] is True
    assert rows[0]["metadata"]["compartmentId"] == "ocid1.compartment.oc1..testing"


def test_oci_network_resource_mapping_preserves_vcn_relationship():
    rows = provider_reconciliation._oci_resources_from_response(
        "subnet",
        {
            "data": [
                {
                    "id": "ocid1.subnet.oc1..abc",
                    "display-name": "ff10-proxy-subnet",
                    "lifecycle-state": "AVAILABLE",
                    "vcn-id": "ocid1.vcn.oc1..ff10",
                    "freeform-tags": {
                        "barragan": "true",
                        "barragan_engagement": "FF10",
                    },
                    "compartment-id": "ocid1.compartment.oc1..testing",
                }
            ]
        },
        "us-sanjose-1",
    )

    assert rows[0]["provider"] == "oci"
    assert rows[0]["resourceType"] == "subnet"
    assert rows[0]["resourceId"] == "ocid1.subnet.oc1..abc"
    assert rows[0]["engagementName"] == "FF10"
    assert rows[0]["metadata"]["vcnId"] == "ocid1.vcn.oc1..ff10"


def test_oci_live_adapter_is_read_only_and_scoped(monkeypatch):
    monkeypatch.setattr(
        provider_reconciliation,
        "resolve_oci_cli",
        lambda env=None: type("Resolution", (), {"ok": True, "command": "oci"})(),
    )
    calls = []

    def runner(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, '{"data": []}', "")

    provider_reconciliation._discover_oci_resources(runner=runner)

    assert ["compute", "instance", "list"] in [call[5:8] for call in calls]
    assert ["network", "vcn", "list"] in [call[5:8] for call in calls]
    assert ["network", "subnet", "list"] in [call[5:8] for call in calls]
    assert ["network", "internet-gateway", "list"] in [call[5:8] for call in calls]
    assert ["network", "route-table", "list"] in [call[5:8] for call in calls]
    assert ["network", "security-list", "list"] in [call[5:8] for call in calls]
    assert ["bv", "boot-volume", "list"] in [call[5:8] for call in calls]
    assert all("--compartment-id" in call for call in calls)
    assert all("delete" not in call and "terminate" not in call for call in calls)


def test_production_oci_inventory_reads_testing_and_four_allowlisted_compartments(monkeypatch):
    monkeypatch.setattr(
        provider_reconciliation,
        "resolve_oci_cli",
        lambda env=None: type("Resolution", (), {"ok": True, "command": "oci"})(),
    )
    monkeypatch.setattr(provider_reconciliation, "runtime_value", lambda *_args, **_kwargs: "production")
    monkeypatch.setattr(
        provider_reconciliation,
        "allowed_oci_deployment_targets",
        lambda _environment: tuple(
            SimpleNamespace(
                auth="instance_principal",
                region="us-sanjose-1",
                compartment_id=f"ocid1.compartment.oc1..configured{index}",
                validate=lambda: None,
            )
            for index in range(5)
        ),
    )
    calls = []

    def runner(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, '{"data": []}', "")

    provider_reconciliation._discover_oci_resources(runner=runner)

    compartment_ids = {
        call[call.index("--compartment-id") + 1]
        for call in calls
    }
    assert len(calls) == 35
    assert len(compartment_ids) == 5


def _engagement(engagement_id: str, name: str) -> StoredEngagement:
    return StoredEngagement(
        id=engagement_id,
        name=name,
        status="active",
        owner="operator",
        template_id="standard-rti",
        active_revision=None,
        input_parameters={},
    )


def _job(
    job_id: str,
    action: str,
    status: str,
    engagement_id: str,
    events: list[JobEvent],
) -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action=action,
        status=status,
        target=f"engagement:{engagement_id}",
        target_type="engagement",
        target_id=engagement_id,
        requested_by="operator",
        input={"engagementId": engagement_id},
        artifact_refs=[],
        created_at="2026-06-09T00:00:00+00:00",
        started_at="2026-06-09T00:00:00+00:00",
        finished_at="2026-06-09T00:01:00+00:00" if status != "running" else None,
        events=events,
    )
