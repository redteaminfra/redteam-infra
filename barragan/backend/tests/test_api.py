# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.integrations.oci_read_validation import BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID, BARRAGAN_TESTING_COMPARTMENT_ID
from app.integrations.pilot_standard_rti import pilot_channel_rows, pilot_names
from app.services.outbound_channel_artifacts import derive_pending_outbound_channel_from_sketch_rows
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import SketchChainModel
from app.storage.service_repository import SqlAlchemyEngagementServiceRepository, StoredEngagementService


@pytest.fixture(autouse=True)
def isolated_credential_store(monkeypatch):
    from app.services.credentials import test_master_key
    monkeypatch.setenv("BARRAGAN_CREDENTIAL_MASTER_KEY", test_master_key())


def _stub_provider_ingress_sync(monkeypatch):
    from app.services.sketch_provider_firewall import ProviderIngressSyncResult

    monkeypatch.setattr(
        "app.services.inbound_channel_apply.sync_provider_ingress_for_inbound_channel",
        lambda *args, **kwargs: ProviderIngressSyncResult(
            status="synced",
            ok=True,
            provider="linode",
            chain_id="chain-1",
            events=(),
            plan=None,
        ),
    )


def test_health_endpoint(client):
    response = client.get("/api/health")
    body = response.get_json()

    assert response.status_code == 200
    assert body["service"] == "barragan-api"
    assert body["status"] == "ok"
    assert body["database"]["uriScheme"] == "sqlite"
    assert body["database"]["path"]
    assert body["database"]["seedStatus"] in {"seeded", "not_seeded"}


def test_inbound_managed_runtime_endpoint_returns_read_only_projection(client, monkeypatch):
    monkeypatch.setattr(
        "app.asgi.get_inbound_managed_runtime",
        lambda engagement_id, channel_id: {
            "routeId": channel_id,
            "channelId": channel_id,
            "mode": "tcp-forward",
            "routingOwner": {"kind": "dedicated-stream", "label": "Dedicated stream forward", "managedBy": "Barragan"},
            "selectedPath": {"chainId": "chain-1", "edge": "edge-1", "middle": "middle-1", "proxy": "proxy01"},
            "externalListener": {"host": "edge-1", "port": "8443", "protocol": "TCP"},
            "termination": {"host": "homebase", "port": "9443", "service": "Operator service"},
            "site": None,
            "certificate": None,
            "managedArtifacts": [],
            "artifactStatus": "recorded",
            "validation": {"status": "Validated"},
            "latestJob": None,
            "readOnly": True,
        },
    )

    response = client.get("/api/engagements/eng-1/inbound-channels/route-1/managed-runtime")

    assert response.status_code == 200
    assert response.get_json()["routeId"] == "route-1"
    assert response.get_json()["readOnly"] is True


def test_templates_endpoint(client):
    response = client.get("/api/templates")
    body = response.get_json()

    assert response.status_code == 200
    assert body["templates"][0]["id"] == "standard-rti"
    assert "oci" in body["templates"][0]["supportedProviders"]


def test_template_detail_endpoint(client):
    response = client.get("/api/templates/standard-rti")
    body = response.get_json()

    assert response.status_code == 200
    assert body["template"]["id"] == "standard-rti"
    assert body["template"]["providerConstraints"]["coreProvider"] == "oci"
    assert body["template"]["routeDefaults"]["minimumIngressRoutes"] == 1


def test_template_validation_accepts_standard_rti_baseline(client):
    response = client.post("/api/templates/standard-rti/validate", json=valid_standard_rti_payload())
    body = response.get_json()

    assert response.status_code == 200
    assert body["validation"]["valid"] is True


def test_template_validation_rejects_unsupported_provider(client):
    payload = valid_standard_rti_payload()
    payload["sketchChains"][0]["middleProvider"] = "oci"

    response = client.post("/api/templates/standard-rti/validate", json=payload)
    body = response.get_json()

    assert response.status_code == 400
    assert body["validation"]["valid"] is False
    assert "sketchChains[0].middleProvider" in body["validation"]["errors"][0]


def test_engagements_endpoint_returns_seed_data(client):
    response = client.get("/api/engagements")
    body = response.get_json()

    assert response.status_code == 200
    assert body["engagements"][0]["templateId"] == "standard-rti"


def test_create_engagement_endpoint_persists_draft(client):
    response = client.post(
        "/api/engagements",
        json={
            "templateId": "standard-rti",
            "owner": "operator@example.invalid",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["engagement"]["status"] == "draft"
    assert body["engagement"]["templateId"] == "standard-rti"

    detail_response = client.get(f"/api/engagements/{body['engagement']['id']}")
    detail_body = detail_response.get_json()
    assert detail_response.status_code == 200
    assert detail_body["engagement"]["name"] == "of02-dev"


def test_create_engagement_seeds_template_sketch_chains(client):
    payload = valid_standard_rti_payload()
    payload["engagementName"] = "test-06"
    payload["proxyCount"] = 1
    payload["sketchChains"] = [
        {
            "id": "chain-1",
            "assignedProxy": "proxy01",
            "middleProvider": "linode",
            "edgeProvider": "linode",
            "middleRegion": "us-sea",
            "edgeRegion": "us-sea",
            "middleSize": "g6-nanode-1",
            "edgeSize": "g6-nanode-1",
            "edgeCount": 3,
        }
    ]
    payload["egressProfiles"] = []
    payload["ingressRoutes"] = []

    response = client.post(
        "/api/engagements",
        json={
            "templateId": "dev-infra",
            "owner": "operator@example.invalid",
            "inputParameters": payload,
        },
    )
    engagement_id = response.get_json()["engagement"]["id"]

    assert response.status_code == 201
    chains_response = client.get(f"/api/engagements/{engagement_id}/sketch-chains")
    chains = chains_response.get_json()["sketchChains"]
    assert chains_response.status_code == 200
    assert len(chains) == 1
    assert chains[0]["chainId"] == "proxy01-sea-01"
    assert chains[0]["edgeCount"] == 3
    assert chains[0]["status"] == "pending"


def test_configure_infrastructure_seeds_template_sketch_chains_idempotently(client):
    create_response = client.post("/api/engagements", json={"name": "test-06", "owner": "operator@example.invalid"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    payload = {
        "engagementName": "test-06",
        "proxyCount": 1,
        "elkEnabled": False,
        "sketchChains": [
            {
                "id": "chain-1",
                "assignedProxy": "proxy01",
                "middleProvider": "linode",
                "edgeProvider": "linode",
                "middleRegion": "us-sea",
                "edgeRegion": "us-sea",
                "middleSize": "g6-nanode-1",
                "edgeSize": "g6-nanode-1",
                "edgeCount": 3,
            }
        ],
        "egressProfiles": [],
        "ingressRoutes": [],
        "reverseChannels": [],
    }

    first = client.post(
        f"/api/engagements/{engagement_id}/infrastructure",
        json={"templateId": "dev-infra", "inputParameters": payload},
    )
    second = client.post(
        f"/api/engagements/{engagement_id}/infrastructure",
        json={"templateId": "dev-infra", "inputParameters": payload},
    )
    chains = client.get(f"/api/engagements/{engagement_id}/sketch-chains").get_json()["sketchChains"]

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(chains) == 1
    assert chains[0]["chainId"] == "proxy01-sea-01"


def test_create_metadata_only_engagement_and_manage_lifecycle(client):
    create_response = client.post(
        "/api/engagements",
        json={
            "name": "ZY01",
            "owner": "example_operator",
            "description": "Training exercise",
            "documentationUrl": "https://docs.example.invalid/zy01",
            "jiraUrl": "https://jira.example.invalid/browse/ZY01",
        },
    )
    body = create_response.get_json()

    assert create_response.status_code == 201
    assert body["engagement"]["name"] == "ZY01"
    assert body["engagement"]["templateId"] is None
    assert body["engagement"]["description"] == "Training exercise"

    engagement_id = body["engagement"]["id"]
    update_response = client.patch(
        f"/api/engagements/{engagement_id}",
        json={
            "name": "ZY01-updated",
            "owner": "operator",
            "description": "Updated metadata",
            "documentationUrl": "https://docs.example.invalid/zy01-updated",
            "jiraUrl": "https://jira.example.invalid/browse/ZY01-1",
        },
    )
    assert update_response.status_code == 200
    assert update_response.get_json()["engagement"]["name"] == "ZY01-updated"
    assert update_response.get_json()["engagement"]["description"] == "Updated metadata"

    archive_response = client.post(f"/api/engagements/{engagement_id}/archive")
    assert archive_response.status_code == 200
    assert archive_response.get_json()["engagement"]["status"] == "archived"

    default_list = client.get("/api/engagements").get_json()["engagements"]
    all_list = client.get("/api/engagements?scope=all").get_json()["engagements"]
    assert engagement_id not in {engagement["id"] for engagement in default_list}
    assert engagement_id in {engagement["id"] for engagement in all_list}

    delete_response = client.delete(f"/api/engagements/{engagement_id}")
    assert delete_response.status_code == 200
    assert delete_response.get_json()["engagement"]["status"] == "retired"

    detail_response = client.get(f"/api/engagements/{engagement_id}")
    assert detail_response.status_code == 200
    assert detail_response.get_json()["engagement"]["status"] == "retired"


def test_delete_engagement_rejects_active_infrastructure(client, monkeypatch):
    create_response = client.post(
        "/api/engagements",
        json={"name": "ZY01", "owner": "example_operator"},
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(StoredJobRun(
            id="job-active-infra", action="pilot_standard_rti_guarded_execute", status="running",
            target=f"engagement:{engagement_id}", target_type="engagement", target_id=engagement_id,
            requested_by="operator", input={"engagementId": engagement_id}, artifact_refs=[], events=[],
            created_at="2026-10-28T12:00:00Z", started_at="2026-10-28T12:00:01Z", finished_at=None,
        ))

    delete_response = client.delete(f"/api/engagements/{engagement_id}")
    body = delete_response.get_json()

    assert delete_response.status_code == 409
    assert "active infrastructure" in body["error"]
    assert body["activeInfrastructure"]["jobId"]


def test_metadata_only_engagement_can_be_configured_for_infrastructure(client):
    create_response = client.post(
        "/api/engagements",
        json={"name": "ZY01", "owner": "example_operator"},
    )
    engagement_id = create_response.get_json()["engagement"]["id"]

    configure_response = client.post(
        f"/api/engagements/{engagement_id}/infrastructure",
        json={
            "templateId": "standard-rti",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    configure_body = configure_response.get_json()

    assert configure_response.status_code == 200
    assert configure_body["engagement"]["templateId"] == "standard-rti"
    assert configure_body["engagement"]["inputParameters"]["proxyCount"] == 2

    revision_response = client.post(f"/api/engagements/{engagement_id}/revisions")
    assert revision_response.status_code == 201
    assert revision_response.get_json()["revision"]["templateId"] == "standard-rti"


def test_engagement_operations_dashboard_uses_recorded_operator_sections(client):
    payload = valid_standard_rti_payload()
    payload["ingressRoutes"][0].update(
        {
            "protocol": "TCP",
            "externalPort": 443,
            "internalPort": 8001,
            "terminatesOn": "proxy01-zy01",
            "service": "SSH Backflips",
            "purpose": "operator access",
        }
    )
    create_response = client.post(
        "/api/engagements",
        json={
            "name": "ZY01",
            "owner": "example_operator",
            "templateId": "standard-rti",
            "inputParameters": payload,
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy01-ops",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={
                    "engagementId": engagement_id,
                    "target": {"region": "us-sanjose-1"},
                },
                artifact_refs=[],
                created_at="2026-06-03T12:00:00+00:00",
                started_at="2026-06-03T12:01:00+00:00",
                finished_at="2026-06-03T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operator inspection ready",
                        {
                            "connectionDetails": [
                                {
                                    "role": "homebase",
                                    "displayName": "homebase-zy01",
                                    "sshAlias": "homebase-zy01",
                                    "publicIp": "203.0.113.10",
                                    "privateIp": "192.168.0.10",
                                    "sshUser": "user",
                                    "services": ["SSH", "Mythic"],
                                },
                                {
                                    "role": "proxy",
                                    "displayName": "proxy01-zy01",
                                    "sshAlias": "proxy01-zy01",
                                    "publicIp": "203.0.113.11",
                                    "privateIp": "192.168.2.11",
                                    "sshUser": "user",
                                    "services": ["SSH"],
                                },
                            ],
                            "servicePlacements": [
                                {
                                    "hostId": "proxy01",
                                    "hostRole": "proxy",
                                    "service": "SSH Backflips",
                                    "status": "Configured",
                                    "port": "2222",
                                }
                            ],
                            "sketchInfrastructure": [
                                {
                                    "chainId": "chain-1",
                                    "hostname": "middle-zy01",
                                    "provider": "linode",
                                    "role": "middle",
                                    "status": "healthy",
                                }
                            ],
                            "outboundChannels": [
                                {
                                    "chainId": "chain-1",
                                    "proxy": "proxy01-zy01",
                                    "middle": "middle-zy01",
                                    "edge": "Not Deployed",
                                    "port": "3333",
                                    "domain": "example.invalid",
                                    "purpose": "operator route",
                                    "status": "Not Ready",
                                }
                            ],
                            "inboundChannels": [
                                {
                                    "channelId": "default-ingress",
                                    "domain": "example.invalid",
                                    "protocol": "TCP",
                                    "externalPort": "443",
                                    "edge": "Not Deployed",
                                    "middle": "middle-zy01",
                                    "proxy": "proxy01-zy01",
                                    "terminatesOn": "proxy01-zy01",
                                    "service": "SSH Backflips",
                                    "internalPort": "8001",
                                    "purpose": "operator access",
                                    "status": "Not Ready",
                                }
                            ],
                        },
                    )
                ],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    operations = response.get_json()["operations"]

    assert response.status_code == 200
    assert operations["coreInfrastructure"][0]["hostname"] == "homebase-zy01"
    assert operations["coreInfrastructure"][0]["health"]["status"] == "healthy"
    assert operations["coreInfrastructure"][0]["region"] == "us-sanjose-1"
    assert operations["coreInfrastructure"][1]["region"] == "us-sanjose-1"
    assert operations["coreInfrastructure"][1]["services"] == ["SSH", "SSH Backflips"]
    assert operations["outboundChannels"][0]["proxy"] == "proxy01-zy01"
    assert operations["outboundChannels"][0]["edge"] == "Not Deployed"
    assert operations["outboundChannels"][0]["domain"] == "example.invalid"
    assert "backflip" not in operations["outboundChannels"][0]["purpose"].lower()
    assert operations["inboundChannels"][0]["domain"] == "example.invalid"
    assert operations["inboundChannels"][0]["externalPort"] == "443"
    assert operations["inboundChannels"][0]["internalPort"] == "8001"
    assert operations["inboundChannels"][0]["terminatesOn"] == "proxy01-zy01"
    assert operations["inboundChannels"][0]["service"] == "SSH Backflips"
    assert operations["inboundChannels"][0]["edge"] == "Not Deployed"
    assert "domains" not in operations
    assert "backflips" not in operations
    assert "targets" not in operations
    assert operations["sketchInfrastructure"][0]["provider"] == "linode"
    ssh_config = operations["sshConfig"]["stanza"]
    assert "Host homebase-zy01" in ssh_config
    assert "Host proxy01-zy01\n    HostName proxy01.infra.redteam" in ssh_config
    assert "ProxyJump homebase-zy01" in ssh_config
    assert "IdentityFile" not in ssh_config
    assert "IdentitiesOnly" not in ssh_config
    assert "    User " not in ssh_config
    assert "# LocalForward 5901 127.0.0.1:59xx" in ssh_config
    assert "Your port number is (5900 + (UID - 6000) + 1)" in ssh_config


def test_engagement_operations_dashboard_does_not_show_planned_inputs_as_live_data(client):
    create_response = client.post(
        "/api/engagements",
        json={
            "name": "ZY01",
            "owner": "example_operator",
            "templateId": "standard-rti",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    operations = response.get_json()["operations"]

    assert response.status_code == 200
    assert operations["coreInfrastructure"] == []
    assert operations["sketchInfrastructure"] == []
    assert operations["outboundChannels"] == []
    assert operations["inboundChannels"] == []
    assert operations["sshConfig"]["stanza"] == ""


def test_engagement_operations_dashboard_uses_deployment_recorded_channel_rows(client):
    create_response = client.post(
        "/api/engagements",
        json={
            "name": "ZY01",
            "owner": "example_operator",
            "templateId": "standard-rti",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    rows = pilot_channel_rows(pilot_names("ZY01"), region="us-sanjose-1")
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy01-pilot-channels",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={"engagementId": engagement_id, "target": {"region": "us-sanjose-1"}},
                artifact_refs=[],
                created_at="2026-06-03T12:00:00+00:00",
                started_at="2026-06-03T12:01:00+00:00",
                finished_at="2026-06-03T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pilot Standard RTI run finished",
                        {
                            "ok": True,
                            "mutationStatus": "deployed",
                            "ansibleStatus": "validated",
                            "finalCleanupStatus": "pending_operator_teardown",
                            **rows,
                        },
                    )
                ],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    operations = response.get_json()["operations"]

    assert response.status_code == 200
    assert operations["outboundChannels"] == rows["outboundChannels"]
    assert operations["inboundChannels"] == rows["inboundChannels"]


def test_engagement_operations_hides_legacy_unconfigured_default_backflip(client):
    create_response = client.post(
        "/api/engagements",
        json={
            "name": "ZY02",
            "owner": "example_operator",
            "templateId": "standard-rti",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    rows = pilot_channel_rows(pilot_names("ZY02"), region="us-sanjose-1")
    rows["inboundChannels"] = [
        {
            "channelId": "default-backflip",
            "domain": "Not Deployed",
            "protocol": "TCP",
            "externalPort": "443",
            "edge": "Not Deployed",
            "middle": "Not Deployed",
            "proxy": "proxy01-zy02",
            "terminatesOn": "proxy01-zy02",
            "service": "SSH Backflips",
            "internalPort": "2222",
            "purpose": "reverse-channel ingress intent",
            "status": "Not Ready",
        }
    ]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy02-legacy-backflip",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={"engagementId": engagement_id, "target": {"region": "us-sanjose-1"}},
                artifact_refs=[],
                created_at="2026-06-03T12:00:00+00:00",
                started_at="2026-06-03T12:01:00+00:00",
                finished_at="2026-06-03T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pilot Standard RTI run finished",
                        {
                            "ok": True,
                            "mutationStatus": "deployed",
                            **rows,
                        },
                    )
                ],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    operations = response.get_json()["operations"]

    assert response.status_code == 200
    assert operations["inboundChannels"] == []


def test_engagement_operations_ignores_later_configured_default_backflip_placeholder(client):
    create_response = client.post(
        "/api/engagements",
        json={"name": "ZY03", "owner": "example_operator", "templateId": "standard-rti", "inputParameters": valid_standard_rti_payload()},
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    real_channel = {
        "channelId": "edge-80-to-web",
        "domain": "site.invalid",
        "protocol": "TCP",
        "externalPort": "80",
        "edge": "edge-zy03",
        "middle": "middle-zy03",
        "proxy": "proxy01-zy03",
        "terminatesOn": "proxy01-zy03",
        "service": "Static Web",
        "internalPort": "18080",
        "purpose": "site web traffic",
        "status": "Validated",
    }
    placeholder = {
        "channelId": "default-backflip",
        "domain": "Not Deployed",
        "protocol": "TCP",
        "externalPort": "443",
        "edge": "Not Deployed",
        "middle": "Not Deployed",
        "proxy": "proxy01",
        "terminatesOn": "proxy01",
        "service": "SSH Backflips",
        "internalPort": "2222",
        "purpose": "legacy placeholder",
        "status": "Configured",
    }
    with client.application.storage_context():
        repository = SqlAlchemyJobRepository()
        for job_id, created_at, action, channels in (
            ("job-zy03-inbound", "2026-06-03T12:00:00+00:00", "inbound_channel_apply", [real_channel]),
            ("job-zy03-backflips", "2026-06-03T13:00:00+00:00", "backflips_service_apply", [placeholder]),
        ):
            repository.save(
                StoredJobRun(
                    id=job_id,
                    action=action,
                    status="succeeded",
                    target=f"engagement:{engagement_id}",
                    target_type="engagement",
                    target_id=engagement_id,
                    requested_by="operator",
                    input={"engagementId": engagement_id},
                    artifact_refs=[],
                    created_at=created_at,
                    started_at=created_at,
                    finished_at=created_at,
                    events=[JobEvent(1, "info", "finished", {"inboundChannels": channels})],
                )
            )

    response = client.get(f"/api/engagements/{engagement_id}/operations")

    assert response.status_code == 200
    assert response.get_json()["operations"]["inboundChannels"] == [{
        **real_channel, "edgeComponentId": "", "middleComponentId": "",
        "rawRouteLegacy": {"schemaVersion": 0, "provenance": "legacy-behavior-fallback",
                           "transport": "tcp", "middleRelayPort": "80", "proxyRelayPort": "80", "migrationRequired": True},
    }]


def test_engagement_operations_dashboard_merges_live_sketch_provider_outbound_channels(client):
    create_response = client.post("/api/engagements", json={"name": "FF07", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    proxy01_channel = _pending_outbound_channel(
        "FF07",
        "proxy01-sea-01",
        proxy="proxy01",
        middle_ip="198.51.100.20",
        edge_ip="198.51.100.30",
    )
    proxy02_channel = _pending_outbound_channel(
        "FF07",
        "proxy02-sea-01",
        proxy="proxy02",
        middle_ip="198.51.100.40",
        edge_ip="198.51.100.50",
    )
    proxy02_channel["provider"] = "digitalocean"
    destroyed_channel = _pending_outbound_channel(
        "FF07",
        "proxy01-sea-02",
        proxy="proxy01",
        middle_ip="198.51.100.60",
        edge_ip="198.51.100.70",
    )

    with client.application.storage_context():
        db.session.add_all(
            [
                _sketch_chain_model(engagement_id, "proxy01-sea-01", "proxy01", "linode", "deployed"),
                _sketch_chain_model(engagement_id, "proxy02-sea-01", "proxy02", "digitalocean", "deployed"),
                _sketch_chain_model(engagement_id, "proxy01-sea-02", "proxy01", "linode", "destroyed"),
            ]
        )
        db.session.commit()
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id="job-ff07-core",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={"engagementId": engagement_id, "target": {"region": "us-sanjose-1"}},
                artifact_refs=[],
                created_at="2026-06-05T12:00:00+00:00",
                started_at="2026-06-05T12:01:00+00:00",
                finished_at="2026-06-05T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pilot Standard RTI run finished",
                        {"outboundChannels": [{"chainId": "chain-1", "proxy": "proxy01", "status": "Not Ready"}]},
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id="job-ff07-linode",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id, "chainId": "proxy01-sea-01"},
                artifact_refs=[],
                created_at="2026-06-05T12:10:00+00:00",
                started_at="2026-06-05T12:10:00+00:00",
                finished_at="2026-06-05T12:15:00+00:00",
                events=[JobEvent(1, "info", "pending outbound channel artifacts derived", {"outboundChannels": [proxy01_channel]})],
            )
        )
        repository.save(
            StoredJobRun(
                id="job-ff07-destroyed",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id, "chainId": "proxy01-sea-02"},
                artifact_refs=[],
                created_at="2026-06-05T12:20:00+00:00",
                started_at="2026-06-05T12:20:00+00:00",
                finished_at="2026-06-05T12:25:00+00:00",
                events=[JobEvent(1, "info", "pending outbound channel artifacts derived", {"outboundChannels": [destroyed_channel]})],
            )
        )
        repository.save(
            StoredJobRun(
                id="job-ff07-digitalocean",
                action="digitalocean_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id, "chainId": "proxy02-sea-01"},
                artifact_refs=[],
                created_at="2026-06-05T12:30:00+00:00",
                started_at="2026-06-05T12:30:00+00:00",
                finished_at="2026-06-05T12:35:00+00:00",
                events=[JobEvent(1, "info", "pending outbound channel artifacts derived", {"outboundChannels": [proxy02_channel]})],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    channels = response.get_json()["operations"]["outboundChannels"]

    assert response.status_code == 200
    assert [channel["chainId"] for channel in channels] == ["proxy01-sea-01", "proxy02-sea-01"]
    assert [channel["port"] for channel in channels] == ["3333", "3333"]
    assert {channel["proxy"] for channel in channels} == {"proxy01", "proxy02"}
    assert {channel["provider"] for channel in channels} == {"linode", "digitalocean"}


def test_engagement_operations_dashboard_keeps_durable_outbound_channels_after_new_core_run(client):
    create_response = client.post("/api/engagements", json={"name": "BUGS01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    chain = _sketch_chain_model(engagement_id, "proxy01-sea-01", "proxy01", "linode", "deployed")
    chain.nodes = [
        {
            "chainId": "proxy01-sea-01",
            "hostname": "middle-bugs01-proxy01-sea-01",
            "provider": "linode",
            "role": "middle",
            "publicIp": "198.51.100.20",
            "region": "us-central",
            "proxy": "proxy01",
            "status": "deployed",
        },
        {
            "chainId": "proxy01-sea-01",
            "hostname": "edge-bugs01-us-sea-proxy01-sea-01",
            "provider": "linode",
            "role": "edge",
            "publicIp": "198.51.100.30",
            "region": "us-sea",
            "proxy": "proxy01",
            "status": "deployed",
        },
    ]

    with client.application.storage_context():
        db.session.add(chain)
        db.session.commit()
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id="job-bugs01-sketch",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id, "chainId": "proxy01-sea-01"},
                artifact_refs=[],
                created_at="2026-06-08T19:07:51+00:00",
                started_at="2026-06-08T19:07:51+00:00",
                finished_at="2026-06-08T19:09:31+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {"outboundChannels": [_pending_outbound_channel("BUGS01", "proxy01-sea-01", proxy="proxy01")]},
                    )
                ],
            )
        )
        stale_validated_channel = _pending_outbound_channel("BUGS01", "proxy01-sea-01", proxy="proxy01")
        stale_validated_channel["status"] = "Validated"
        stale_validated_channel["validation"] = {
            **stale_validated_channel["validation"],
            "status": "Validated",
            "checkedAt": "2026-06-08T20:26:06+00:00",
            "lastCheckedAt": "2026-06-08T20:26:06+00:00",
        }
        repository.save(
            StoredJobRun(
                id="job-bugs01-stale-outbound-validation",
                action="outbound_channel_validation",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id, "chainId": "proxy01-sea-01"},
                artifact_refs=[],
                created_at="2026-06-08T20:26:06+00:00",
                started_at="2026-06-08T20:26:06+00:00",
                finished_at="2026-06-08T20:26:07+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "outbound channel validation succeeded",
                        {"outboundChannels": [stale_validated_channel]},
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id="job-bugs01-new-core",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={"engagementId": engagement_id, "target": {"region": "us-sanjose-1"}},
                artifact_refs=[],
                created_at="2026-06-08T20:29:07+00:00",
                started_at="2026-06-08T20:29:07+00:00",
                finished_at="2026-06-08T20:30:17+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pilot Standard RTI run finished",
                        {"connectionDetails": [], "outboundChannels": []},
                    )
                ],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    channels = response.get_json()["operations"]["outboundChannels"]

    assert response.status_code == 200
    assert [channel["chainId"] for channel in channels] == ["proxy01-sea-01"]
    assert channels[0]["proxy"] == "proxy01"
    assert channels[0]["middle"] == "middle-bugs01-proxy01-sea-01"
    assert channels[0]["edge"] == "edge-bugs01-us-sea-proxy01-sea-01"
    assert channels[0]["port"] == "3333"
    assert channels[0]["status"] == "Pending Proxy Configuration"


def test_engagement_operations_dashboard_keeps_compact_outbound_metadata_without_artifacts(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy01-sketch-channels",
                action="linode_sketch_deploy",
                status="succeeded",
                target="engagement:zy01",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={
                    "engagementId": engagement_id,
                    "chainId": "chain-1",
                    "sshPrivateKeyPath": "/tmp/barragan-keys/zy01-sketch",
                },
                artifact_refs=[],
                created_at="2026-06-04T12:00:00+00:00",
                started_at="2026-06-04T12:01:00+00:00",
                finished_at="2026-06-04T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {
                            "outboundChannels": [
                                {
                                    "chainId": "chain-1",
                                    "proxy": "proxy01",
                                    "middle": "middle-zy01",
                                    "edge": "edge-zy01",
                                    "port": "3333",
                                    "region": "us-sea",
                                    "provider": "linode",
                                    "domain": "chain-1",
                                    "purpose": "Sketch egress profile chain-1",
                                    "status": "Pending Proxy Configuration",
                                    "profileName": "chain-1",
                                    "publicationPath": "/opt/proxy01/chain-1-socks5.conf",
                                    "validation": {
                                        "origin": "homebase",
                                        "command": ["curl", "-sS", "--connect-timeout", "10", "-x", "socks5h://proxy01:3333", "https://ipv4.icanhazip.com"],
                                        "shellDisplay": "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
                                        "expectedPublicIp": "203.0.113.20",
                                    },
                                    "artifactTargets": {
                                        "homebaseProxychains": "/opt/proxy01/chain-1-socks5.conf",
                                        "proxySshConfig": "/opt/ssh-proxy/config-3333",
                                        "proxySystemdService": "/etc/systemd/system/ssh-proxy-3333.service",
                                    },
                                    "artifacts": {
                                        "homebaseProxychains": {
                                            "target": "/opt/proxy01/chain-1-socks5.conf",
                                            "content": "strict_chain\nsocks5 192.168.2.11 3333\n",
                                        },
                                        "proxySshConfig": {
                                            "target": "/opt/ssh-proxy/config-3333",
                                            "content": "DynamicForward 0.0.0.0:3333\n",
                                        },
                                    },
                                }
                            ],
                        },
                    )
                ],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    channel = response.get_json()["operations"]["outboundChannels"][0]

    assert response.status_code == 200
    assert channel["chainId"] == "chain-1"
    assert channel["status"] == "Pending Proxy Configuration"
    assert channel["profileName"] == "chain-1"
    assert channel["publicationPath"] == "/opt/proxy01/chain-1-socks5.conf"
    assert channel["validation"] == {
        "origin": "homebase",
        "shellDisplay": "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
        "expectedPublicIp": "203.0.113.20",
        "command": ["curl", "-sS", "--connect-timeout", "10", "-x", "socks5h://proxy01:3333", "https://ipv4.icanhazip.com"],
    }
    assert channel["artifactTargets"] == {
        "homebaseProxychains": "/opt/proxy01/chain-1-socks5.conf",
        "proxySshConfig": "/opt/ssh-proxy/config-3333",
        "proxySystemdService": "/etc/systemd/system/ssh-proxy-3333.service",
    }
    assert "artifacts" not in channel
    assert "DynamicForward" not in str(channel)


def test_outbound_channel_apply_preview_renders_core_only_workspace_and_job(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    outbound_channel = _pending_outbound_channel("ZY01", "chain-1")
    with client.application.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id="job-zy01-core",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:00:00+00:00",
                started_at="2026-06-04T12:01:00+00:00",
                finished_at="2026-06-04T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operator inspection ready",
                        {
                            "workspaceDir": str(client.application.state.config.DATA_DIR / "core-workspace"),
                            "connectionDetails": [
                                {
                                    "role": "homebase",
                                    "displayName": "homebase-zy01",
                                    "sshAlias": "homebase-zy01",
                                    "publicIp": "203.0.113.10",
                                    "privateIp": "192.168.0.10",
                                    "sshUser": "user",
                                },
                                {
                                    "role": "proxy01",
                                    "displayName": "proxy01-zy01",
                                    "sshAlias": "proxy01-zy01",
                                    "publicIp": "203.0.113.11",
                                    "privateIp": "192.168.2.11",
                                    "sshUser": "user",
                                },
                            ]
                        },
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id="job-zy01-outbound",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {"outboundChannels": [outbound_channel]},
                    )
                ],
            )
        )

    _seed_bootstrapped_outbound_chain(client, engagement_id, "job-zy01-outbound")

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/apply-preview",
        json={"requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["action"] == "outbound_channel_apply_preview"
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["input"] == {"engagementId": engagement_id, "channelId": "chain-1", "chainId": "chain-1", "mutation": False}
    assert body["workspace"]["status"] == "Pending Core Apply"
    assert body["workspace"]["mutation"] is False
    inventory = body["workspace"]["inventory"]["content"]
    playbook = body["workspace"]["playbook"]["content"]
    assert "homebase ansible_host=203.0.113.10 ansible_user=user" in inventory
    assert "proxy01 ansible_host=192.168.2.11 ansible_user=user" in inventory
    assert "middle-zy01-chain-1 ansible_host" not in inventory
    assert "edge-zy01-chain-1 ansible_host" not in inventory
    assert "dest: /opt/proxy01/chain-1-socks5.conf" in playbook
    assert "dest: /opt/ssh-proxy/config-3333" in playbook
    assert "ProxyJump middle-zy01-chain-1" in playbook
    assert "hosts: middle-zy01-chain-1" not in playbook
    assert "hosts: edge-zy01-chain-1" not in playbook
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "linode-token" not in str(body)

    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "outbound_channel_apply_preview" and job.input.get("engagementId") == engagement_id
        ]
    assert len(jobs) == 1
    assert jobs[0].events[0].data["mutation"] is False
    assert jobs[0].events[0].data["status"] == "Pending Core Apply"


def test_outbound_channel_apply_preview_requires_core_connection_details(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy01-outbound",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {"outboundChannels": [_pending_outbound_channel("ZY01", "chain-1")]},
                    )
                ],
            )
        )

    _seed_bootstrapped_outbound_chain(client, engagement_id, "job-zy01-outbound")

    response = client.post(f"/api/engagements/{engagement_id}/outbound-channels/chain-1/apply-preview")

    assert response.status_code == 400
    assert "homebase connection details are required before outbound apply preview" in response.get_json()["errors"]
    assert "proxy01 connection details are required before outbound apply preview" in response.get_json()["errors"]


def test_outbound_channel_apply_preview_requires_rendered_artifacts(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy01-outbound",
                action="engagement_channels_update",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "engagement channels updated",
                        {"outboundChannels": [{"chainId": "chain-1", "proxy": "proxy01"}]},
                    )
                ],
            )
        )

    response = client.post(f"/api/engagements/{engagement_id}/outbound-channels/chain-1/apply-preview")

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["outbound channel chain-1 with rendered artifacts was not found"]


def test_outbound_channel_apply_requires_confirmation_before_mutation_job(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/apply",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be apply-outbound-chain-1"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "outbound_channel_apply" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_outbound_channel_apply_route_runs_single_ansible_command_and_records_job(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, stdout="applied", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.outbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.outbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "outbound-workspaces")

    from app.services.sketch_provider_firewall import ProviderIngressSyncResult
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.sync_provider_ingress_for_transport",
        lambda *args, **kwargs: ProviderIngressSyncResult(
            status="synced", ok=True, provider="linode", chain_id="chain-1", events=(), plan=None
        ),
    )

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/apply",
        json={"confirmation": "apply-outbound-chain-1", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Pending Validation"
    assert body["job"]["action"] == "outbound_channel_apply"
    assert body["job"]["status"] == "succeeded"
    assert len(calls) == 1
    assert calls[0][0] == [
        str(ansible_playbook),
        "-i",
        "ansible/inventory.ini",
        "ansible/apply_outbound_channel.yml",
    ]
    assert [event["message"] for event in body["job"]["events"]] == [
        "outbound channel apply workspace rendered",
        "outbound channel Ansible apply started",
        "outbound channel Ansible apply succeeded",
        "outbound channel validation pending",
    ]
    assert body["job"]["events"][-1]["data"]["status"] == "Pending Validation"
    assert body["job"]["events"][-1]["data"]["validationRan"] is False
    persisted = str(body)
    assert "BEGIN OPENSSH PRIVATE KEY" not in persisted
    assert "LINODE_TOKEN" not in persisted
    assert "provider_token" not in persisted
    updated_channel = body["job"]["events"][-1]["data"]["outboundChannels"][0]
    assert updated_channel["status"] == "Pending Validation"
    assert updated_channel["validation"]["status"] == "Pending Validation"
    assert updated_channel["validation"]["detail"] == "Core channel config applied; homebase validation has not run yet."
    assert "artifacts" not in updated_channel
    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    assert operations["outboundChannels"][0]["status"] == "Pending Validation"
    assert operations["outboundChannels"][0]["validation"]["status"] == "Pending Validation"
    assert "artifacts" not in operations["outboundChannels"][0]


def test_outbound_channel_apply_preserves_other_outbound_channels(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, stdout="applied", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.outbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.outbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "outbound-workspaces")

    from app.services.sketch_provider_firewall import ProviderIngressSyncResult
    monkeypatch.setattr(
        "app.services.outbound_channel_apply.sync_provider_ingress_for_transport",
        lambda *args, **kwargs: ProviderIngressSyncResult(
            status="synced", ok=True, provider="linode", chain_id="chain-1", events=(), plan=None
        ),
    )

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(
        client,
        engagement_id,
        outbound_channels=[
            _pending_outbound_channel("ZY01", "chain-1", proxy="proxy01", middle_ip="203.0.113.20", edge_ip="203.0.113.30"),
            _pending_outbound_channel("ZY01", "chain-2", proxy="proxy02", middle_ip="203.0.113.40", edge_ip="203.0.113.50"),
        ],
    )

    _seed_bootstrapped_outbound_chain(
        client, engagement_id, f"job-{engagement_id}-outbound", chain_id="chain-2", proxy="proxy02",
        middle_ip="203.0.113.40", edge_ip="203.0.113.50",
    )

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-2/apply",
        json={"confirmation": "apply-outbound-chain-2", "requestedBy": "operator"},
    )

    assert response.status_code == 202
    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    channels = {channel["chainId"]: channel for channel in operations["outboundChannels"]}
    assert set(channels) == {"chain-1", "chain-2"}
    assert channels["chain-1"]["status"] == "Pending Proxy Configuration"
    assert channels["chain-2"]["status"] == "Pending Validation"
    assert channels["chain-2"]["validation"]["status"] == "Pending Validation"


def test_outbound_channel_apply_route_requires_rendered_artifacts(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/apply",
        json={"confirmation": "apply-outbound-chain-1"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["outbound channel chain-1 with rendered artifacts was not found"]


def test_outbound_channel_validate_requires_confirmation_before_validation_job(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/validate",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be validate-outbound-chain-1"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "outbound_channel_validation" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_outbound_channel_validate_route_runs_homebase_ansible_and_updates_overview(client, tmp_path, monkeypatch):
    ansible = _make_executable(tmp_path, "ansible")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        inventory = (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        assert "[homebase]" in inventory
        assert "[selected_proxy]" not in inventory
        assert "proxy01 ansible_host" not in inventory
        assert "middle-zy01-chain-1 ansible_host" not in inventory
        assert "edge-zy01-chain-1 ansible_host" not in inventory
        if "%{http_code}" in command[-1]:
            return subprocess.CompletedProcess(command, 0, stdout="200\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout="203.0.113.30\n", stderr="")

    monkeypatch.setenv("ANSIBLE_BIN", str(ansible))
    monkeypatch.setattr("app.services.outbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.outbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "outbound-workspaces")

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/validate",
        json={"confirmation": "validate-outbound-chain-1", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Validated"
    assert body["job"]["action"] == "outbound_channel_validation"
    assert body["job"]["status"] == "succeeded"
    assert len(calls) == 6
    assert calls[0][0] == [
        str(ansible),
        "-i",
        "ansible/inventory.ini",
        "homebase",
        "-m",
        "ansible.builtin.command",
        "-a",
        "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
    ]
    assert [call[0][-1].split()[-1] for call in calls[1:]] == [
        "https://ifconfig.me",
        "https://www.google.com",
        "https://www.cnn.com",
        "https://www.amazon.com",
        "https://www.facebook.com",
    ]
    assert [event["message"] for event in body["job"]["events"]] == [
        "outbound channel validation workspace rendered",
        "outbound channel homebase validation started",
        "outbound channel validation succeeded",
    ]
    evidence = body["job"]["events"][-1]["data"]["validationEvidence"]
    assert evidence["origin"] == "homebase"
    assert evidence["inventoryTargets"] == ["homebase"]
    assert evidence["expectedPublicIp"] == "203.0.113.30"
    assert evidence["observedPublicIp"] == "203.0.113.30"
    assert evidence["status"] == "Validated"
    assert [probe["url"] for probe in evidence["httpProbes"]] == [
        "https://ifconfig.me",
        "https://www.google.com",
        "https://www.cnn.com",
        "https://www.amazon.com",
        "https://www.facebook.com",
    ]
    assert all(probe["ok"] for probe in evidence["httpProbes"])
    assert "artifacts" not in body["job"]["events"][-1]["data"]["outboundChannels"][0]

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    channel = operations["outboundChannels"][0]
    assert channel["chainId"] == "chain-1"
    assert channel["status"] == "Validated"
    assert channel["validation"]["status"] == "Validated"
    assert channel["validation"]["checkedAt"]
    assert channel["validation"]["expectedPublicIp"] == "203.0.113.30"
    assert "artifacts" not in channel


def test_outbound_channel_validate_route_records_mismatch_without_claiming_validation(client, tmp_path, monkeypatch):
    ansible = _make_executable(tmp_path, "ansible")

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, stdout="198.51.100.99\n", stderr="")

    monkeypatch.setenv("ANSIBLE_BIN", str(ansible))
    monkeypatch.setattr("app.services.outbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.outbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "outbound-workspaces")

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/validate",
        json={"confirmation": "validate-outbound-chain-1"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Validation Failed"
    assert body["job"]["status"] == "failed"
    evidence = body["job"]["events"][-1]["data"]["validationEvidence"]
    assert evidence["expectedPublicIp"] == "203.0.113.30"
    assert evidence["observedPublicIp"] == "198.51.100.99"
    assert evidence["status"] == "Validation Failed"
    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    assert operations["outboundChannels"][0]["status"] == "Validation Failed"
    assert operations["outboundChannels"][0]["validation"]["status"] == "Validation Failed"


def test_outbound_channel_validate_route_requires_homebase_connection_details(client, tmp_path, monkeypatch):
    ansible = _make_executable(tmp_path, "ansible")
    monkeypatch.setenv("ANSIBLE_BIN", str(ansible))
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id="job-zy01-outbound-only",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {"outboundChannels": [_pending_outbound_channel("ZY01", "chain-1")]},
                    )
                ],
            )
        )

    _seed_bootstrapped_outbound_chain(client, engagement_id, "job-zy01-outbound-only")

    response = client.post(
        f"/api/engagements/{engagement_id}/outbound-channels/chain-1/validate",
        json={"confirmation": "validate-outbound-chain-1"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["homebase connection details are required before outbound validation"]


def test_backflips_service_apply_preview_endpoint_renders_core_only_workspace(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/backflips/apply-preview",
        json={"proxyId": "proxy01"},
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["action"] == "backflips_service_apply_preview"
    assert body["workspace"]["inventory"]["target"] == "ansible/inventory.ini"
    assert "[selected_proxy]" in body["workspace"]["inventory"]["content"]
    assert "proxy01 ansible_host=192.168.2.11" in body["workspace"]["inventory"]["content"]
    assert "hosts: selected_proxy" in body["workspace"]["playbook"]["content"]
    assert "roles/backflips_v2" in body["workspace"]["playbook"]["content"]
    assert "middle-" not in body["workspace"]["inventory"]["content"]
    assert "edge-" not in body["workspace"]["inventory"]["content"]
    assert "inboundChannels" not in body["job"]["events"][0]["data"]


def test_backflips_service_apply_endpoint_requires_confirmation(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/backflips/apply",
        json={"proxyId": "proxy01", "confirmation": "wrong"},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert 'confirmation must equal "apply-service-backflips"' in body["errors"]


def test_legacy_keepassxc_service_apply_preview_endpoint_renders_homebase_only_workspace(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/legacy-homebase-roles/keepassxc/apply-preview",
        json={},
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["action"] == "legacy_homebase_role_service_apply_preview"
    assert body["workspace"]["inventory"]["target"] == "ansible/inventory.ini"
    assert "[selected_homebase]" in body["workspace"]["inventory"]["content"]
    assert "homebase ansible_host=203.0.113.10" in body["workspace"]["inventory"]["content"]
    assert "hosts: selected_homebase" in body["workspace"]["playbook"]["content"]
    assert "- role: keepassxc" in body["workspace"]["playbook"]["content"]
    assert "middle-" not in body["workspace"]["inventory"]["content"]
    assert "edge-" not in body["workspace"]["inventory"]["content"]
    assert body["service"]["service"] == "KeePassXC"
    assert body["service"]["hostId"] == "homebase"


def test_legacy_keepassxc_service_apply_endpoint_requires_confirmation(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/legacy-homebase-roles/keepassxc/apply",
        json={"confirmation": "wrong"},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert 'confirmation must equal "apply-service-keepassxc"' in body["errors"]


def test_desktop_service_catalog_endpoint_groups_gui_apps_without_nmap(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.get(f"/api/engagements/{engagement_id}/services/desktop")
    body = response.get_json()

    assert response.status_code == 200
    assert body["service"]["serviceId"] == "desktop"
    slugs = [app["slug"] for app in body["apps"]]
    assert slugs == ["google-chrome", "firefox", "vs-code", "libreoffice", "keepassxc"]
    assert "nmap" not in slugs


def test_desktop_service_apply_preview_endpoint_renders_homebase_only_workspace(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/desktop/apply-preview",
        json={"desiredApps": [{"slug": "google-chrome", "enabled": True}, {"slug": "firefox", "enabled": False}]},
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["action"] == "desktop_service_apply_preview"
    assert body["confirmation"] == "apply-service-desktop"
    assert body["workspace"]["playbook"]["target"] == "ansible/apply_desktop.yml"
    assert "name: google-chrome" in body["workspace"]["playbook"]["content"]
    assert "Remove Desktop app package Firefox" in body["workspace"]["playbook"]["content"]
    assert "middle-" not in body["workspace"]["inventory"]["content"]
    assert "edge-" not in body["workspace"]["inventory"]["content"]
    assert [placement["service"] for placement in body["servicePlacements"]] == ["Google Chrome", "Firefox"]


def test_desktop_service_apply_endpoint_does_not_require_confirmation(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    def fake_apply(engagement_id_arg, body, **kwargs):
        assert engagement_id_arg == engagement_id
        assert body["desiredApps"] == [{"slug": "google-chrome", "enabled": True}]
        assert "confirmation" not in kwargs
        return {"job": {"id": "job-desktop-apply", "status": "succeeded", "events": []}, "status": "Configured", "servicePlacements": []}

    monkeypatch.setattr("app.asgi.apply_desktop_service", fake_apply)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/desktop/apply",
        json={"desiredApps": [{"slug": "google-chrome", "enabled": True}]},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["job"]["id"] == "job-desktop-apply"


def test_web_static_service_apply_preview_endpoint_renders_proxy_web_workspace(client, monkeypatch):
    inspected = []
    def inspect(intent, proxy, runner=None):
        inspected.append((intent.site_name, proxy.name, proxy.proxy_jump))
        return {"state": "existing", "fingerprint": "a" * 64, "entryCount": 2, "bytes": 128}
    monkeypatch.setattr("app.services.web_static_service._inspect_remote_content", inspect)
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/services/web-static/apply-preview",
        json={
            "proxyId": "proxy01",
            "siteName": "ff10",
            "domain": "ff10.example.invalid",
            "internalPort": "8081",
            "indexHtml": "<html><body>hola ff10</body></html>\n",
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["action"] == "web_static_service_apply_preview"
    assert body["service"]["serviceType"] == "web-static"
    assert body["service"]["config"]["contentPath"] == "/opt/web/ff10/html/"
    assert body["service"]["config"]["indexPath"] == "/opt/web/ff10/html/index.html"
    assert body["workspace"]["inventory"]["target"] == "ansible/inventory.ini"
    assert "proxy01 ansible_host=192.168.2.11" in body["workspace"]["inventory"]["content"]
    assert "Apply reviewed Static Web content policy" in body["workspace"]["playbook"]["content"]
    assert "../helpers/static_web_content.py" in body["workspace"]["playbook"]["content"]
    assert inspected == [("ff10", "proxy01", "user@203.0.113.10")]
    assert body["contentReview"]["state"] == "existing"
    assert body["contentReview"]["defaultAction"] == "preserve"
    assert body["contentReview"]["reviewJobId"] == body["job"]["id"]
    assert body["job"]["input"]["contentReview"]["fingerprint"] == "a" * 64
    assert "files/opt/web/ff10/html/index.html" in [artifact["target"] for artifact in body["workspace"]["artifacts"]]
    assert "middle-" not in body["workspace"]["inventory"]["content"]
    assert "edge-" not in body["workspace"]["inventory"]["content"]


def test_services_endpoint_and_operations_expose_durable_web_static_service(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)
    with client.application.storage_context():
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=engagement_id,
                service_id="web-ff10",
                service_type="web-static",
                name="ff10",
                proxy_id="proxy01",
                status="Configured",
                config={
                    "siteName": "ff10",
                    "domain": "ff10.example.invalid",
                    "internalPort": 18080,
                    "contentPath": "/opt/web/ff10/html/index.html",
                    "siteConfigPath": "/opt/web/ff10/conf/default.conf",
                    "composePath": "/opt/web/barragan-ff10.compose.yml",
                },
            )
        )

    services_response = client.get(f"/api/engagements/{engagement_id}/services")
    operations_response = client.get(f"/api/engagements/{engagement_id}/operations")

    assert services_response.status_code == 200
    assert services_response.get_json()["services"][0]["serviceId"] == "web-ff10"
    assert operations_response.status_code == 200
    operations = operations_response.get_json()["operations"]
    assert operations["servicePlacements"][0]["service"] == "Static Web"
    assert operations["servicePlacements"][0]["port"] == "18080"
    proxy01 = next(host for host in operations["coreInfrastructure"] if host["hostname"] == "proxy01-zy01")
    assert "Static Web" in proxy01["services"]


def test_operations_core_summary_ignores_stale_static_web_service_events_after_remove(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id=f"job-{engagement_id}-stale-web",
                action="web_static_service_apply",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:20:00+00:00",
                started_at="2026-06-04T12:20:00+00:00",
                finished_at="2026-06-04T12:21:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "legacy static web service placement recorded",
                        {
                            "servicePlacements": [
                                {
                                    "hostId": "proxy01",
                                    "hostRole": "proxy",
                                    "service": "Static Web",
                                    "status": "Configured",
                                    "port": "18080",
                                }
                            ]
                        },
                    )
                ],
            )
        )
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=engagement_id,
                service_id="web-ff10",
                service_type="web-static",
                name="ff10",
                proxy_id="proxy01",
                status="Removed",
                config={
                    "siteName": "ff10",
                    "domain": "ff10.example.invalid",
                    "internalPort": 18080,
                    "contentPath": "/opt/web/ff10/html/",
                    "indexPath": "/opt/web/ff10/html/index.html",
                    "siteConfigPath": "/opt/web/ff10/conf/default.conf",
                    "composePath": "/opt/web/barragan-ff10.compose.yml",
                },
            )
        )

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]

    proxy01 = next(host for host in operations["coreInfrastructure"] if host["hostname"] == "proxy01-zy01")
    assert "Static Web" not in proxy01["services"]


def test_web_static_service_remove_preview_endpoint_renders_proxy_only_workspace(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)
    with client.application.storage_context():
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=engagement_id,
                service_id="web-ff10",
                service_type="web-static",
                name="ff10",
                proxy_id="proxy01",
                status="Configured",
                config={
                    "siteName": "ff10",
                    "domain": "ff10.example.invalid",
                    "internalPort": 18080,
                    "contentPath": "/opt/web/ff10/html/index.html",
                    "siteConfigPath": "/opt/web/ff10/conf/default.conf",
                    "composePath": "/opt/web/barragan-ff10.compose.yml",
                },
            )
        )

    response = client.post(f"/api/engagements/{engagement_id}/services/web-static/web-ff10/remove-preview", json={})
    body = response.get_json()

    assert response.status_code == 201
    assert body["confirmationToken"] == "remove-web-ff10"
    assert body["job"]["action"] == "web_static_service_remove_preview"
    assert body["workspace"]["status"] == "Pending Service Removal"
    assert body["workspace"]["playbook"]["target"] == "ansible/remove_web_static.yml"
    assert "/opt/web/ff10/html" in body["workspace"]["playbook"]["content"]
    assert "middle-" not in body["workspace"]["inventory"]["content"]
    assert "edge-" not in body["workspace"]["inventory"]["content"]


def test_web_static_service_remove_endpoint_requires_confirmation(client, monkeypatch):
    monkeypatch.setattr(
        "app.services.web_static_service.resolve_ansible_playbook",
        lambda env=None: type("Resolution", (), {"ok": True, "command": "ansible-playbook", "message": ""})(),
    )
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_outbound_apply_prerequisites(client, engagement_id)
    with client.application.storage_context():
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=engagement_id,
                service_id="web-ff10",
                service_type="web-static",
                name="ff10",
                proxy_id="proxy01",
                status="Configured",
                config={
                    "siteName": "ff10",
                    "domain": "ff10.example.invalid",
                    "internalPort": 18080,
                },
            )
        )

    response = client.delete(
        f"/api/engagements/{engagement_id}/services/web-static/web-ff10",
        json={"confirmation": "wrong"},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert 'confirmation must equal "remove-web-ff10"' in body["errors"]


def test_engagement_operations_combines_core_and_latest_sketch_jobs(client):
    create_response = client.post(
        "/api/engagements",
        json={
            "name": "ZY01",
            "owner": "example_operator",
            "templateId": "standard-rti",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id="job-core-zy01",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={"engagementId": engagement_id, "target": {"region": "us-sanjose-1"}},
                artifact_refs=[],
                created_at="2026-06-03T12:00:00+00:00",
                started_at="2026-06-03T12:01:00+00:00",
                finished_at="2026-06-03T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operator inspection ready",
                        {
                            "connectionDetails": [
                                {
                                    "role": "homebase",
                                    "displayName": "homebase-zy01",
                                    "sshAlias": "homebase-zy01",
                                    "publicIp": "203.0.113.10",
                                    "privateIp": "192.168.0.10",
                                    "sshUser": "user",
                                }
                            ]
                        },
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id="job-sketch-zy01",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-03T12:10:00+00:00",
                started_at="2026-06-03T12:11:00+00:00",
                finished_at="2026-06-03T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "terraform output recorded",
                        {
                            "sketchInfrastructure": [
                                {
                                    "chainId": "chain-1",
                                    "hostname": "middle01-zy01",
                                    "provider": "linode",
                                    "role": "middle",
                                    "publicIp": "198.51.100.20",
                                    "region": "us-sea",
                                    "status": "deployed",
                                }
                            ]
                        },
                    )
                ],
            )
        )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    operations = response.get_json()["operations"]

    assert response.status_code == 200
    assert operations["activeJob"]["id"] == "job-sketch-zy01"
    assert operations["coreJob"]["id"] == "job-core-zy01"
    assert operations["coreInfrastructure"][0]["hostname"] == "homebase-zy01"
    assert operations["sketchInfrastructure"][0]["hostname"] == "middle01-zy01"
    assert "Host homebase-zy01" in operations["sshConfig"]["stanza"]


def test_engagement_operations_patch_persists_housekeeping_items_only(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    patch_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "housekeepingItems": "Created proxy route during setup.",
            "ansibleTerraformUrl": "https://example.invalid/ignored",
        },
    )
    get_response = client.get(f"/api/engagements/{engagement_id}/operations")

    assert patch_response.status_code == 200
    assert patch_response.get_json()["operations"]["housekeepingItems"] == "Created proxy route during setup."
    assert get_response.get_json()["operations"]["housekeepingItems"] == "Created proxy route during setup."
    assert "ansibleTerraformUrl" not in get_response.get_json()["operations"]


def test_engagement_operations_patch_records_operator_channels(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    patch_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "housekeepingItems": "Channels reviewed by operator.",
            "outboundChannels": [
                {
                    "proxy": "proxy01-zy01",
                    "middle": "middle01-zy01",
                    "edge": "edge01-zy01",
                    "listenerPort": 3333,
                    "region": "us-sea",
                    "provider": "linode",
                    "domain": "egress.example.invalid",
                    "purpose": "operator route",
                    "status": "ready",
                    "apiToken": "must-not-persist",
                }
            ],
            "inboundChannels": [
                {
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "externalPort": 443,
                    "edge": "edge01-zy01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": 7443,
                    "purpose": "C2",
                    "status": "ready",
                    "secret": "must-not-persist",
                }
            ],
        },
    )
    get_response = client.get(f"/api/engagements/{engagement_id}/operations")

    assert patch_response.status_code == 200
    operations = get_response.get_json()["operations"]
    assert get_response.status_code == 200
    assert operations["housekeepingItems"] == "Channels reviewed by operator."
    assert operations["outboundChannels"] == [
        {
            "channelId": "outbound-egress-example-invalid-proxy01-zy01-middle01-zy01-edge01-zy01-3333",
            "chainId": "outbound-egress-example-invalid-proxy01-zy01-middle01-zy01-edge01-zy01-3333",
            "proxy": "proxy01-zy01",
            "middle": "middle01-zy01",
            "edge": "edge01-zy01",
            "port": "3333",
            "region": "us-sea",
            "provider": "linode",
            "domain": "egress.example.invalid",
            "purpose": "operator route",
            "status": "ready",
        }
    ]
    assert operations["inboundChannels"] == [
        {
            "channelId": "inbound-c2-example-invalid-mythic-443-7443",
            "domain": "c2.example.invalid",
            "protocol": "HTTPS",
            "externalPort": "443",
            "edge": "edge01-zy01",
            "edgeComponentId": "",
            "middle": "middle01-zy01",
            "middleComponentId": "",
            "proxy": "proxy01-zy01",
            "terminatesOn": "homebase-zy01",
            "service": "Mythic",
            "internalPort": "7443",
            "purpose": "C2",
            "status": "ready",
        }
    ]

    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "engagement_channels_update" and job.input.get("engagementId") == engagement_id
        ]
    assert len(jobs) == 1
    assert jobs[0].status == "succeeded"
    assert jobs[0].events[0].data["outboundChannels"][0]["port"] == "3333"
    assert jobs[0].events[0].data["inboundChannels"][0]["externalPort"] == "443"
    assert "must-not-persist" not in str(jobs[0].to_detail().to_dict())


def test_engagement_operations_rejects_route_edits_for_applied_inbound_channels(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    channel = {
        "channelId": "c2-primary",
        "domain": "c2.example.invalid",
        "protocol": "HTTPS",
        "mode": "tcp-forward",
        "externalPort": "443",
        "edge": "edge01-zy01",
        "middle": "middle01-zy01",
        "proxy": "proxy01-zy01",
        "terminatesOn": "proxy01-zy01",
        "service": "OpenResty",
        "internalPort": "18080",
        "purpose": "C2 ingress",
        "status": "Validated",
    }
    first_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": [channel]},
    )

    edit_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": [{**channel, "externalPort": "8080"}]},
    )

    assert first_response.status_code == 200
    assert edit_response.status_code == 400
    assert edit_response.get_json()["errors"] == [
        "applied inbound channel c2-primary cannot change live route fields externalPort; remove it first, then record a new channel"
    ]
    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    assert operations["inboundChannels"][0]["externalPort"] == "443"


def test_engagement_operations_rejects_generic_delete_or_disable_for_applied_inbound_channels(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    channel = {
        "channelId": "c2-primary",
        "domain": "c2.example.invalid",
        "protocol": "HTTPS",
        "mode": "tcp-forward",
        "externalPort": "443",
        "edge": "edge01-zy01",
        "middle": "middle01-zy01",
        "proxy": "proxy01-zy01",
        "terminatesOn": "proxy01-zy01",
        "service": "OpenResty",
        "internalPort": "18080",
        "purpose": "C2 ingress",
        "status": "Pending Validation",
    }
    first_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": [channel]},
    )
    delete_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": []},
    )
    disable_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": [{**channel, "status": "Disabled"}]},
    )

    assert first_response.status_code == 200
    assert delete_response.status_code == 400
    assert disable_response.status_code == 400
    assert delete_response.get_json()["errors"] == [
        "applied inbound channel c2-primary must be removed with the inbound channel remove workflow before deleting the record"
    ]
    assert disable_response.get_json()["errors"] == [
        "applied inbound channel c2-primary must be removed with the inbound channel remove workflow before changing status to Disabled"
    ]


def test_engagement_operations_allows_shared_web_inbound_channels_on_same_listener(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    channels = [
        {
            "channelId": "web-edge-1",
            "domain": "web-one.example.invalid",
            "protocol": "HTTP",
            "mode": "tcp-forward",
            "routeFamily": "shared-web-ingress",
            "sharedWebIngress": True,
            "routingOwner": "proxy-front-openresty",
            "externalPort": "80",
            "relayPort": "80",
            "middleRelayPort": "80",
            "proxyRelayPort": "80",
            "edge": "edge-zy01-us-sea-01",
            "middle": "middle01-zy01",
            "proxy": "proxy01-zy01",
            "terminatesOn": "proxy01-zy01",
            "service": "Static Web",
            "serviceId": "web-one",
            "serviceType": "web-static",
            "internalPort": "18081",
            "purpose": "Static web one",
            "status": "Pending Validation",
        },
        {
            "channelId": "web-edge-2",
            "domain": "web-two.example.invalid",
            "protocol": "HTTP",
            "mode": "tcp-forward",
            "externalPort": "80",
            "relayPort": "80",
            "middleRelayPort": "80",
            "proxyRelayPort": "80",
            "edge": "edge-zy01-us-sea-02",
            "middle": "middle01-zy01",
            "proxy": "proxy01-zy01",
            "terminatesOn": "proxy01-zy01",
            "service": "Static Web",
            "serviceId": "web-two",
            "serviceType": "web-static",
            "internalPort": "18082",
            "purpose": "Static web two",
            "status": "Pending Apply",
        },
    ]

    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": channels},
    )

    assert response.status_code == 200
    inbound = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]["inboundChannels"]
    assert [channel["channelId"] for channel in inbound] == ["web-edge-1", "web-edge-2"]
    assert inbound[0]["routeFamily"] == "shared-web-ingress"
    assert inbound[0]["sharedWebIngress"] is True
    assert inbound[0]["routingOwner"] == "proxy-front-openresty"


def test_engagement_operations_rejects_dedicated_inbound_conflict_with_shared_web_listener(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    shared = {
        "channelId": "web-edge-1",
        "domain": "web-one.example.invalid",
        "protocol": "HTTP",
        "mode": "tcp-forward",
        "externalPort": "80",
        "relayPort": "80",
        "middleRelayPort": "80",
        "proxyRelayPort": "80",
        "edge": "edge-zy01-us-sea-01",
        "middle": "middle01-zy01",
        "proxy": "proxy01-zy01",
        "terminatesOn": "proxy01-zy01",
        "service": "Static Web",
        "internalPort": "18081",
        "purpose": "Static web one",
        "status": "Pending Validation",
    }
    dedicated = {
        **shared,
        "channelId": "raw-edge-1",
        "domain": "raw.example.invalid",
        "protocol": "TCP",
        "service": "Raw TCP",
        "internalPort": "18090",
    }

    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={"inboundChannels": [shared, dedicated]},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == [
        "inbound channel raw-edge-1 conflicts with web-edge-1 on edge edge-zy01-us-sea-01:80/tcp",
        "inbound channel raw-edge-1 conflicts with web-edge-1 on middle middle01-zy01:80/tcp",
        "inbound channel raw-edge-1 conflicts with web-edge-1 on proxy proxy01-zy01:80/tcp",
    ]


def test_engagement_operations_preserves_removed_shared_web_channel_when_service_removed(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyEngagementServiceRepository().save(
            StoredEngagementService(
                engagement_id=engagement_id,
                service_id="web-one",
                service_type="web-static",
                name="web-one",
                proxy_id="proxy01",
                status="Removed",
                config={"siteName": "web-one", "domain": "web-one.example.invalid", "internalPort": 18081},
            )
        )
    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "web-edge-1",
                    "domain": "web-one.example.invalid",
                    "protocol": "HTTP",
                    "mode": "tcp-forward",
                    "routeFamily": "shared-web-ingress",
                    "sharedWebIngress": True,
                    "routingOwner": "proxy-front-openresty",
                    "externalPort": "80",
                    "relayPort": "80",
                    "middleRelayPort": "80",
                    "proxyRelayPort": "80",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "Static Web",
                    "serviceId": "web-one",
                    "serviceType": "web-static",
                    "internalPort": "18081",
                    "purpose": "Static web one",
                    "status": "Removed",
                    "validation": {"status": "Removed", "detail": "Shared web inbound channel record removed."},
                }
            ]
        },
    )

    assert response.status_code == 200
    channel = response.get_json()["operations"]["inboundChannels"][0]
    assert channel["status"] == "Removed"
    assert channel["validation"]["status"] == "Removed"
    assert "Service Not Ready" not in str(channel)


def test_engagement_operations_preserves_raw_tcp_validation_request_text(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    request_text = "GET / HTTP/1.1\r\nHost: c2.example.invalid\r\n\r\n"

    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "OpenResty",
                    "internalPort": "7443",
                    "purpose": "C2 ingress",
                    "status": "Pending Validation",
                    "validationProfile": {
                        "type": "tcp-send-receive",
                        "label": "Raw TCP request",
                        "requestText": request_text,
                        "expectedResponse": "hola ff10",
                    },
                }
            ]
        },
    )

    assert response.status_code == 200
    operations = response.get_json()["operations"]
    assert operations["inboundChannels"][0]["validationProfile"]["requestText"] == request_text


def test_engagement_operations_rejects_unsupported_inbound_validation_profile(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "externalPort": "443",
                    "terminatesOn": "homebase-zy01",
                    "service": "OpenResty",
                    "internalPort": "7443",
                    "validationProfile": {
                        "type": "http-body-match",
                        "label": "HTTP body match",
                        "expectedResponse": "hola",
                    },
                }
            ]
        },
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["validationProfile.type must be temporary-listener, tcp-send-receive, udp-send-receive, tcp-connect, http, or manual"]


def test_engagement_operations_rejects_secret_bearing_validation_profile_text(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    for request_text in (
        "GET / HTTP/1.1\r\nAuthorization: Bearer sensitive\r\n\r\n",
        "api_key=sensitive",
        "private_key = sensitive",
        "token = sensitive",
    ):
        response = client.patch(
            f"/api/engagements/{engagement_id}/operations",
            json={
                "inboundChannels": [
                    {
                        "channelId": "c2-primary",
                        "domain": "c2.example.invalid",
                        "protocol": "HTTPS",
                        "externalPort": "443",
                        "terminatesOn": "homebase-zy01",
                        "service": "OpenResty",
                        "internalPort": "7443",
                        "validationProfile": {
                            "type": "tcp-send-receive",
                            "requestText": request_text,
                            "expectedResponse": "hola",
                        },
                    }
                ]
            },
        )

        assert response.status_code == 400
        assert response.get_json()["errors"] == ["validationProfile.requestText appears to contain credential material"]


def test_engagement_operations_rejects_duplicate_active_inbound_edge_ports(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "externalPort": "443",
                    "edge": "edge01-zy01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": "7443",
                    "status": "Not Ready",
                },
                {
                    "channelId": "c2-secondary",
                    "domain": "c2b.example.invalid",
                    "protocol": "HTTPS",
                    "externalPort": "443",
                    "edge": "edge01-zy01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "OpenResty",
                    "internalPort": "8443",
                    "status": "Pending Apply",
                },
            ],
        },
    )

    assert response.status_code == 400
    assert "conflicts with c2-primary on edge edge01-zy01:443" in response.get_json()["errors"][0]


def test_engagement_operations_rejects_duplicate_active_inbound_middle_or_proxy_ports(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "edge-a-web",
                    "domain": "a.example.invalid",
                    "protocol": "HTTPS",
                    "externalPort": "443",
                    "edge": "edge-a-zy01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "OpenResty",
                    "internalPort": "8001",
                    "status": "Not Ready",
                },
                {
                    "channelId": "edge-b-web",
                    "domain": "b.example.invalid",
                    "protocol": "HTTPS",
                    "externalPort": "443",
                    "edge": "edge-b-zy01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "OpenResty",
                    "internalPort": "8002",
                    "status": "Not Ready",
                },
            ],
        },
    )

    assert response.status_code == 400
    errors = response.get_json()["errors"]
    assert any("conflicts with edge-a-web on middle middle01-zy01:443" in error for error in errors)
    assert any("conflicts with edge-a-web on proxy proxy01-zy01:443" in error for error in errors)


def test_inbound_channel_apply_preview_endpoint_renders_non_mutating_route_workspace(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": "7443",
                    "purpose": "C2 ingress",
                    "status": "Not Ready",
                },
                {
                    "channelId": "c2-secondary",
                    "domain": "c2b.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "8443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "OpenResty",
                    "internalPort": "9443",
                    "purpose": "second ingress",
                    "status": "Not Ready",
                },
            ]
        },
    )

    response = client.post(f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply-preview", json={})
    body = response.get_json()

    assert response.status_code == 201
    assert body["job"]["action"] == "inbound_channel_apply_preview"
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["input"]["mutation"] is False
    channel = body["workspace"]["channel"]
    assert channel["status"] == "Pending Apply"
    assert channel["mode"] == "tcp-forward"
    ingress_assessment = body["workspace"]["ingressAssessment"]
    checks = {check["scope"]: check for check in ingress_assessment["checks"]}
    assert ingress_assessment["status"] == "allowed"
    assert ingress_assessment["applyAllowed"] is True
    assert checks["edgeProviderIngress"]["status"] == "managed"
    assert checks["edgeHostFirewall"]["status"] == "managed"
    assert checks["middleHostFirewall"]["status"] == "managed"
    assert checks["proxyHostFirewall"]["status"] == "managed"
    assert checks["coreProxyCloudIngress"]["status"] == "allowed"
    assert checks["terminationListenerExpectation"]["status"] == "unknown"
    assert channel["ingressAssessment"] == ingress_assessment
    assert channel["artifactTargets"] == {
        "edgeStream": "/etc/nginx/streams/barragan-c2-primary-edge-443.conf",
        "middleStream": "/etc/nginx/streams/barragan-c2-primary-middle-443.conf",
        "proxyStream": "/etc/nginx/streams/barragan-c2-primary-proxy-443.conf",
    }
    artifacts = body["workspace"]["artifacts"]
    assert "proxy_pass 198.51.100.20:443;" in artifacts["edgeStream"]["content"]
    assert "proxy_protocol on;" not in artifacts["edgeStream"]["content"]
    assert "proxy_pass 203.0.113.11:443;" in artifacts["middleStream"]["content"]
    assert "proxy_pass 192.168.0.10:7443;" in artifacts["proxyStream"]["content"]
    assert artifacts["validation"]["listenerOrigin"] == "homebase-zy01"
    assert artifacts["validation"]["probeOrigin"] == "selected_edge"
    assert artifacts["validation"]["validationScope"] == "edge-local ingress route"
    assert artifacts["validation"]["externalIngressVerified"] is False
    assert "nc -l 0.0.0.0 7443" in artifacts["validation"]["listenerShellDisplay"]
    assert "nc -w 5 127.0.0.1 443" in artifacts["validation"]["probeShellDisplay"]
    apply_workspace = body["workspace"]["applyWorkspace"]
    assert apply_workspace["inventory"]["target"] == "ansible/inventory.ini"
    assert "proxy01-zy01 ansible_host=proxy01-zy01" in apply_workspace["inventory"]["content"]
    assert "middle01-zy01 ansible_host=middle01-zy01" in apply_workspace["inventory"]["content"]
    assert "edge-zy01-us-sea-01 ansible_host=edge-zy01-us-sea-01" in apply_workspace["inventory"]["content"]
    assert "-F ansible/ssh_config" in apply_workspace["inventory"]["content"]
    assert "Host proxy01-zy01" in apply_workspace["sshConfig"]["content"]
    assert "    HostName 192.168.2.11" in apply_workspace["sshConfig"]["content"]
    assert "    ProxyJump homebase-zy01" in apply_workspace["sshConfig"]["content"]
    assert "Host middle01-zy01" in apply_workspace["sshConfig"]["content"]
    assert "    HostName 198.51.100.20" in apply_workspace["sshConfig"]["content"]
    assert "    ProxyJump proxy01-zy01" in apply_workspace["sshConfig"]["content"]
    assert "Host edge-zy01-us-sea-01" in apply_workspace["sshConfig"]["content"]
    assert "    HostName 198.51.100.30" in apply_workspace["sshConfig"]["content"]
    assert "    ProxyJump middle01-zy01" in apply_workspace["sshConfig"]["content"]
    assert "user@203.0.113.11" not in apply_workspace["inventory"]["content"]
    assert " nc %h %p" not in apply_workspace["inventory"]["content"]
    assert " nc %h %p" not in apply_workspace["sshConfig"]["content"]
    assert "wrong-provider-sketch" not in apply_workspace["inventory"]["content"]
    assert [playbook["target"] for playbook in apply_workspace["playbooks"]] == [
        "ansible/preflight_inbound_channel.yml",
        "ansible/prepare_inbound_hosts.yml",
        "ansible/apply_inbound_channel.yml",
    ]
    assert "hosts: selected_edge" in apply_workspace["playbook"]["content"]
    assert "hosts: selected_middle" in apply_workspace["playbook"]["content"]
    assert "Ensure SSH forwarding support on selected_middle" not in apply_workspace["playbook"]["content"]
    assert "name: netcat-openbsd" not in apply_workspace["playbook"]["content"]
    assert "AllowTcpForwarding yes" not in apply_workspace["playbook"]["content"]
    assert '"directSketchAccessFromAppHost": false' in apply_workspace["manifest"]["content"]
    assert '"resolvedRoute": {' in apply_workspace["manifest"]["content"]
    assert '"ansibleHost": "192.168.2.11"' in apply_workspace["manifest"]["content"]
    assert '"privateIp": "192.168.2.11"' in apply_workspace["manifest"]["content"]
    assert '"proxyJump": "homebase->proxy"' in apply_workspace["manifest"]["content"]
    assert '"proxyJump": "homebase->proxy->middle"' in apply_workspace["manifest"]["content"]
    assert "applyWorkspaceEvidence" in body["job"]["events"][0]["data"]
    assert body["job"]["events"][0]["data"]["ingressAssessment"] == ingress_assessment
    assert "private-key" not in str(body).lower()
    assert "must-not-persist" not in str(body)

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    assert operations["inboundChannels"][0]["status"] == "Pending Apply"
    assert operations["inboundChannels"][0]["validation"]["status"] == "Not Run"
    assert operations["inboundChannels"][0]["artifactTargets"]["edgeStream"].endswith("barragan-c2-primary-edge-443.conf")
    assert [channel["channelId"] for channel in operations["inboundChannels"]] == ["c2-primary", "c2-secondary"]
    assert operations["inboundChannels"][1]["status"] == "Not Ready"


def test_inbound_channel_apply_preview_reports_blocked_core_proxy_ingress_port(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "ff10-file",
                    "domain": "files.example.invalid",
                    "protocol": "TCP",
                    "mode": "tcp-forward",
                    "externalPort": "2121",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "TCP file service",
                    "internalPort": "2121",
                    "purpose": "file transfer ingress",
                    "status": "Not Ready",
                }
            ]
        },
    )

    response = client.post(f"/api/engagements/{engagement_id}/inbound-channels/ff10-file/apply-preview", json={})
    body = response.get_json()

    assert response.status_code == 201
    assessment = body["workspace"]["ingressAssessment"]
    core_check = next(check for check in assessment["checks"] if check["scope"] == "coreProxyCloudIngress")
    assert assessment["status"] == "blocked"
    assert assessment["applyAllowed"] is False
    assert assessment["blockedChecks"] == ["core-proxy-cloud-ingress"]
    assert core_check["status"] == "blocked"
    assert "selected core proxy relay port 2121/tcp is blocked" in core_check["detail"]
    assert "80/tcp, 443/tcp, 2222/tcp, and 8000-8080/tcp" in core_check["detail"]
    assert "core cloud ingress mutation support" in core_check["correctiveAction"]
    assert body["workspace"]["channel"]["ingressAssessment"] == assessment
    assert body["job"]["events"][0]["data"]["ingressAssessment"] == assessment


def test_inbound_channel_apply_preview_renders_udp_forward_relay_port(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "udp-inventory",
                    "domain": "udp.example.invalid",
                    "protocol": "UDP",
                    "mode": "udp-forward",
                    "externalPort": "53",
                    "relayPort": "5454",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "UDP request response",
                    "internalPort": "18080",
                    "purpose": "UDP ingress",
                    "status": "Not Ready",
                    "validationProfile": {
                        "type": "udp-send-receive",
                        "label": "UDP send/expect",
                        "requestText": "PING",
                        "expectedResponse": "FF0000",
                    },
                }
            ]
        },
    )

    response = client.post(f"/api/engagements/{engagement_id}/inbound-channels/udp-inventory/apply-preview", json={})
    body = response.get_json()

    assert response.status_code == 201
    channel = body["workspace"]["channel"]
    assessment = body["workspace"]["ingressAssessment"]
    artifacts = body["workspace"]["artifacts"]
    apply_playbook = body["workspace"]["applyWorkspace"]["playbook"]["content"]

    assert channel["protocol"] == "UDP"
    assert channel["mode"] == "udp-forward"
    assert channel["relayPort"] == "5454"
    assert channel["middleRelayPort"] == "5454"
    assert channel["proxyRelayPort"] == "5454"
    assert assessment["protocol"] == "udp"
    assert assessment["externalPort"] == 53
    assert assessment["proxyRelayPort"] == 5454
    assert assessment["terminationPort"] == 18080
    core_check = next(check for check in assessment["checks"] if check["scope"] == "coreProxyCloudIngress")
    assert core_check["status"] == "blocked"
    assert "selected core proxy relay port 5454/udp is blocked" in core_check["detail"]
    assert "8000-8080/udp" in core_check["detail"]
    assert "listen 53 udp reuseport;" in artifacts["edgeStream"]["content"]
    assert "proxy_pass 198.51.100.20:5454;" in artifacts["edgeStream"]["content"]
    assert "listen 5454 udp reuseport;" in artifacts["middleStream"]["content"]
    assert "proxy_pass 203.0.113.11:5454;" in artifacts["middleStream"]["content"]
    assert "listen 5454 udp reuseport;" in artifacts["proxyStream"]["content"]
    assert "proxy_pass 192.168.0.10:18080;" in artifacts["proxyStream"]["content"]
    assert "proxy_protocol on;" not in str(artifacts)
    assert artifacts["validation"]["profileType"] == "udp-send-receive"
    assert "barragan_transport_protocol: \"udp\"" in apply_playbook
    assert "barragan_middle_listen_port: 5454" in apply_playbook
    assert "Verify UDP inbound listener" in apply_playbook
    assert "hosts: localhost" not in apply_playbook
    assert "barragan-app" not in str(body)


def test_inbound_channel_apply_preview_rejects_unknown_channel_without_job(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(f"/api/engagements/{engagement_id}/inbound-channels/missing/apply-preview", json={})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["inbound channel missing was not found"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_apply_preview" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_inbound_channel_apply_preview_requires_recorded_live_core_route(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": "7443",
                    "purpose": "C2 ingress",
                    "status": "Not Ready",
                }
            ],
        },
    )

    response = client.post(f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply-preview", json={})

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["homebase host homebase was not found in core infrastructure"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_apply_preview" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_inbound_channel_apply_requires_confirmation_before_mutation_job(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be apply-inbound-c2-primary"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_apply" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_inbound_channel_apply_blocks_core_proxy_ingress_before_ansible_mutation(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0, stdout="should-not-run", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")
    _stub_provider_ingress_sync(monkeypatch)

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "ff10-file",
                    "domain": "files.example.invalid",
                    "protocol": "TCP",
                    "mode": "tcp-forward",
                    "externalPort": "2121",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "TCP file service",
                    "internalPort": "2121",
                    "purpose": "file transfer ingress",
                    "status": "Not Ready",
                }
            ]
        },
    )

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/ff10-file/apply",
        json={"confirmation": "apply-inbound-ff10-file", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 400
    assert len(body["errors"]) == 1
    assert "selected core proxy relay port 2121/tcp is blocked" in body["errors"][0]
    assert "Select an allowed relay port" in body["errors"][0]
    assert calls == []
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_apply" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    assert operations["inboundChannels"][0]["status"] == "Not Ready"


def test_inbound_channel_apply_route_runs_ansible_and_automatically_validates(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []
    background_errors = []
    monkeypatch.setattr(client.application.state.config, "ENGAGEMENT_REPOS_ROOT", tmp_path / "engagements")

    def write_sketch_key(_engagement_id, directory):
        directory.mkdir(parents=True, exist_ok=True)
        private_key = directory / "admin"
        public_key = directory / "admin.pub"
        private_key.write_text("test-private-key", encoding="utf-8")
        public_key.write_text("ssh-ed25519 test-public-key", encoding="utf-8")
        return str(private_key), str(public_key)

    def run_background(task):
        try:
            task()
        except Exception as exc:  # pragma: no cover - assertion reports the real background failure
            background_errors.append(exc)

    def runner(command, cwd):
        calls.append((command, cwd))
        if command[-1] == "ansible/validate_inbound_channel.yml":
            validation_playbook = (cwd / command[-1]).read_text(encoding="utf-8")
            assert "Send validation marker from selected edge through inbound route" in validation_playbook
            return subprocess.CompletedProcess(command, 0, stdout="barragan-inbound-c2-primary\n", stderr="")
        inventory = (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        ssh_config = (cwd / "ansible" / "ssh_config").read_text(encoding="utf-8")
        preflight_playbook = (cwd / "ansible" / "preflight_inbound_channel.yml").read_text(encoding="utf-8")
        prepare_playbook = (cwd / "ansible" / "prepare_inbound_hosts.yml").read_text(encoding="utf-8")
        apply_playbook = (cwd / "ansible" / "apply_inbound_channel.yml").read_text(encoding="utf-8")
        manifest = (cwd / "MANIFEST.json").read_text(encoding="utf-8")
        assert "[selected_proxy]" in inventory
        assert "[selected_middle]" in inventory
        assert "[selected_edge]" in inventory
        assert "proxy01-zy01 ansible_host=proxy01-zy01" in inventory
        assert "middle01-zy01 ansible_host=middle01-zy01" in inventory
        assert "edge-zy01-us-sea-01 ansible_host=edge-zy01-us-sea-01" in inventory
        targets_group = inventory.split("[inbound_channel_targets:children]", 1)[1]
        assert "termination_host" in targets_group
        assert "-F ansible/ssh_config" in inventory
        assert "Host proxy01-zy01" in ssh_config
        assert "    HostName 192.168.2.11" in ssh_config
        assert "    ProxyJump homebase-zy01" in ssh_config
        assert "Host middle01-zy01" in ssh_config
        assert "    HostName 198.51.100.20" in ssh_config
        assert "    ProxyJump proxy01-zy01" in ssh_config
        assert "Host edge-zy01-us-sea-01" in ssh_config
        assert "    HostName 198.51.100.30" in ssh_config
        assert "    ProxyJump middle01-zy01" in ssh_config
        assert "user@203.0.113.11" not in inventory
        assert " nc %h %p" not in inventory
        assert " nc %h %p" not in ssh_config
        assert "ansible_ssh_private_key_file=" in inventory
        assert "/keys/admin" in inventory
        assert "wrong-provider-sketch" not in inventory
        assert "Preflight inbound management path for selected_proxy" in preflight_playbook
        assert "Preflight inbound management path for selected_middle" in preflight_playbook
        assert "Preflight inbound management path for selected_edge" in preflight_playbook
        assert "ansible.builtin.apt:" not in preflight_playbook
        assert "Stage engagement sketch SSH key on selected proxy" not in prepare_playbook
        assert "/opt/ssh-proxy/keys/zy01-sketch" not in prepare_playbook
        assert "Install nginx stream support" in prepare_playbook
        assert "hosts: selected_edge" in apply_playbook
        assert "hosts: selected_middle" in apply_playbook
        assert "hosts: selected_proxy" in apply_playbook
        assert "Write Barragan inbound stream config" in apply_playbook
        assert "Install nginx stream support" in apply_playbook
        assert '"directSketchAccessFromAppHost": false' in manifest
        assert '"playbook": "ansible/preflight_inbound_channel.yml"' in manifest
        assert '"playbook": "ansible/prepare_inbound_hosts.yml"' not in manifest
        assert '"playbook": "ansible/apply_inbound_channel.yml"' in manifest
        assert '"resolvedRoute": {' in manifest
        assert '"privateIp": "192.168.2.11"' in manifest
        assert '"proxyJump": "homebase->proxy"' in manifest
        assert '"proxyJump": "homebase->proxy->middle"' in manifest
        return subprocess.CompletedProcess(command, 0, stdout="applied", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", run_background)
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")
    monkeypatch.setattr(
        "app.services.inbound_channel_apply.write_existing_sketch_ssh_key_files",
        write_sketch_key,
    )
    _stub_provider_ingress_sync(monkeypatch)

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply",
        json={"confirmation": "apply-inbound-c2-primary", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202, body
    assert background_errors == []
    assert body["status"] == "Pending Apply"
    assert body["job"]["action"] == "inbound_channel_apply"
    assert body["job"]["status"] == "running"
    assert [call[0] for call in calls] == [
        [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/preflight_inbound_channel.yml"],
        [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/apply_inbound_channel.yml"],
        [str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/validate_inbound_channel.yml"],
    ]
    with client.application.storage_context():
        final_job = SqlAlchemyJobRepository().get(body["job"]["id"])
    assert final_job is not None
    final_body = final_job.to_detail().to_dict()
    assert final_job.status == "succeeded"
    assert [event["message"] for event in final_body["events"]] == [
        "inbound channel apply workspace rendered",
        "inbound channel Ansible apply started",
        "inbound channel apply phase started",
        "inbound channel apply phase succeeded",
        "inbound channel apply phase started",
        "inbound channel apply phase succeeded",
        "inbound channel Ansible apply succeeded",
        "inbound channel validation pending",
    ]
    assert [
        event["data"]["phase"]
        for event in final_body["events"]
        if event["message"] == "inbound channel apply phase succeeded"
    ] == ["preflight", "apply"]
    updated_channel = final_body["events"][-1]["data"]["inboundChannels"][0]
    assert updated_channel["status"] == "Pending Validation"
    assert updated_channel["validation"]["status"] == "Pending Validation"
    assert "temporary listener" in updated_channel["validation"]["detail"]
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "LINODE_TOKEN" not in str(body)
    assert "provider_token" not in str(body)

    with client.application.storage_context():
        validation_jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_validation"
            and job.input.get("engagementId") == engagement_id
            and job.input.get("channelId") == "c2-primary"
        ]
    assert len(validation_jobs) == 1
    assert validation_jobs[0].status == "succeeded"

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    channel = operations["inboundChannels"][0]
    assert channel["channelId"] == "c2-primary"
    assert channel["status"] == "Validated"
    assert channel["validation"]["status"] == "Validated"
    assert channel["validation"]["expectedMarker"] == "barragan-inbound-c2-primary"


def test_inbound_channel_apply_route_enables_automatic_validation(client, monkeypatch):
    calls = []

    def start_apply(engagement_id, channel_id, **kwargs):
        calls.append((engagement_id, channel_id, kwargs))
        return {
            "status": "Pending Apply",
            "job": {"id": "job-inbound-apply", "action": "inbound_channel_apply", "status": "running"},
        }

    monkeypatch.setattr("app.asgi.start_inbound_channel_apply", start_apply)

    response = client.post(
        "/api/engagements/eng-zy01/inbound-channels/c2-primary/apply",
        json={"confirmation": "apply-inbound-c2-primary", "requestedBy": "operator"},
    )

    assert response.status_code == 202
    assert len(calls) == 1
    assert calls[0][0:2] == ("eng-zy01", "c2-primary")
    assert calls[0][2]["auto_validate"] is True


def test_inbound_channel_apply_route_records_failure_without_updating_channel(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append(command)
        return subprocess.CompletedProcess(command, 2, stdout="", stderr="failed")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")
    _stub_provider_ingress_sync(monkeypatch)

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply",
        json={"confirmation": "apply-inbound-c2-primary"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Pending Apply"
    assert body["job"]["status"] == "running"
    with client.application.storage_context():
        final_job = SqlAlchemyJobRepository().get(body["job"]["id"])
    assert final_job is not None
    assert final_job.status == "failed"
    final_body = final_job.to_detail().to_dict()
    assert [event["message"] for event in final_body["events"]][-1] == "inbound channel Ansible apply failed"
    assert calls == [[str(ansible_playbook), "-i", "ansible/inventory.ini", "ansible/preflight_inbound_channel.yml"]]
    assert final_body["events"][-1]["data"]["failedPhase"] == "preflight"
    assert "inboundChannels" not in final_body["events"][-1]["data"]

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    assert operations["inboundChannels"][0]["status"] == "Not Ready"


def test_inbound_channel_validate_requires_confirmation_before_validation_job(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/validate",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be validate-inbound-c2-primary"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_validation" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_inbound_channel_validate_route_runs_edge_probe_and_updates_overview(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        inventory = (cwd / "ansible" / "inventory.ini").read_text(encoding="utf-8")
        ssh_config = (cwd / "ansible" / "ssh_config").read_text(encoding="utf-8")
        playbook = (cwd / "ansible" / "validate_inbound_channel.yml").read_text(encoding="utf-8")
        assert "[selected_edge]" in inventory
        assert "[termination_host]" in inventory
        assert "edge-zy01-us-sea-01 ansible_host=edge-zy01-us-sea-01" in inventory
        assert "-F ansible/ssh_config" in inventory
        assert "Host edge-zy01-us-sea-01" in ssh_config
        assert "    ProxyJump middle01-zy01" in ssh_config
        assert "user@203.0.113.11" not in inventory
        assert " nc %h %p" not in inventory
        assert " nc %h %p" not in ssh_config
        assert f"ansible_ssh_private_key_file={cwd / 'keys' / 'zy01-sketch'}" in inventory
        assert (cwd / "keys" / "zy01-sketch").stat().st_mode & 0o777 == 0o600
        assert "wrong-provider-sketch" not in inventory
        assert "Stage engagement sketch SSH key on selected proxy" not in playbook
        assert "/opt/ssh-proxy/keys/zy01-sketch" not in playbook
        assert "hosts: selected_edge" in playbook
        assert "hosts: localhost" not in playbook
        assert "connection: local" not in playbook
        assert "hosts: termination_host" in playbook
        assert "python3 -c" in playbook
        assert "Wait for temporary listener port" in playbook
        assert "port: 7443" in playbook
        assert "Send validation marker from selected edge through inbound route" in playbook
        assert "127.0.0.1" in playbook
        assert "register: inbound_validation_probe" in playbook
        return subprocess.CompletedProcess(command, 0, stdout="barragan-inbound-c2-primary\n", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")
    _stub_provider_ingress_sync(monkeypatch)

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/validate",
        json={"confirmation": "validate-inbound-c2-primary", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Validated"
    assert body["job"]["action"] == "inbound_channel_validation"
    assert body["job"]["status"] == "succeeded"
    assert len(calls) == 1
    assert calls[0][0] == [
        str(ansible_playbook),
        "-i",
        "ansible/inventory.ini",
        "ansible/validate_inbound_channel.yml",
    ]
    assert [event["message"] for event in body["job"]["events"]] == [
        "inbound channel validation workspace rendered",
        "inbound channel validation started",
        "inbound channel validation succeeded",
    ]
    evidence = body["job"]["events"][-1]["data"]["validationEvidence"]
    assert evidence["listenerOrigin"] == "homebase-zy01"
    assert evidence["probeOrigin"] == "selected_edge"
    assert evidence["validationScope"] == "edge-local ingress route"
    assert evidence["externalIngressVerified"] is False
    assert evidence["ingressEndpoint"] == "127.0.0.1:443"
    assert evidence["expectedMarker"] == "barragan-inbound-c2-primary"
    assert evidence["status"] == "Validated"
    assert "directSketchAccessFromAppHost" in str(body["job"]["events"][0]["data"]["opsecBoundary"])
    assert body["job"]["events"][0]["data"]["opsecBoundary"]["directEdgeProbeFromAppHost"] is False
    assert "BEGIN OPENSSH PRIVATE KEY" not in str(body)
    assert "barragan-app" not in str(body)

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    channel = operations["inboundChannels"][0]
    assert channel["channelId"] == "c2-primary"
    assert channel["status"] == "Validated"
    assert channel["validation"]["status"] == "Validated"
    assert channel["validation"]["checkedAt"]
    assert channel["validation"]["probeOrigin"] == "selected_edge"
    assert channel["validation"]["externalIngressVerified"] is False


def test_inbound_channel_validate_tcp_send_receive_profile_records_evidence(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        playbook = (cwd / "ansible" / "validate_inbound_channel.yml").read_text(encoding="utf-8")
        manifest = (cwd / "MANIFEST.json").read_text(encoding="utf-8")
        manifest_body = json.loads(manifest)
        assert "Start temporary inbound validation listener" not in playbook
        assert "Wait for temporary listener port" not in playbook
        assert "python3 -c" in playbook
        assert "hosts: termination_host" not in playbook
        assert "hosts: selected_edge" in playbook
        assert "hosts: localhost" not in playbook
        assert "connection: local" not in playbook
        assert "Send TCP validation probe from selected edge through inbound route" in playbook
        assert "127.0.0.1" in playbook
        assert "barragan_expected_response in inbound_validation_probe.stdout" in playbook
        assert '"profileType": "tcp-send-receive"' in manifest
        assert '"expectedResponse": "hola ff10"' in manifest
        assert manifest_body["validation"]["validationProfile"]["requestText"] == "GET / HTTP/1.1\r\nHost: c2.example.invalid\r\n\r\n"
        assert manifest_body["validation"]["probeOrigin"] == "selected_edge"
        assert manifest_body["validation"]["externalIngressVerified"] is False
        return subprocess.CompletedProcess(command, 0, stdout="HTTP/1.1 200 OK\r\nAuthorization: Bearer sensitive\r\n\r\nhola ff10\n", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "OpenResty",
                    "internalPort": "7443",
                    "purpose": "C2 ingress",
                    "status": "Pending Validation",
                    "validationProfile": {
                        "type": "tcp-send-receive",
                        "label": "Raw HTTP over TCP",
                        "requestText": "GET / HTTP/1.1\r\nHost: c2.example.invalid\r\n\r\n",
                        "expectedResponse": "hola ff10",
                    },
                }
            ]
        },
    )

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/validate",
        json={"confirmation": "validate-inbound-c2-primary", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Validated"
    assert len(calls) == 1
    evidence = body["job"]["events"][-1]["data"]["validationEvidence"]
    assert evidence["profileType"] == "tcp-send-receive"
    assert evidence["profileLabel"] == "Raw HTTP over TCP"
    assert evidence["expectedResponse"] == "hola ff10"
    assert "hola ff10" in evidence["observedResponse"]
    assert "HTTP/1.1" not in evidence["observedResponse"]
    assert "nc -w 5 127.0.0.1 443" in evidence["probeShellDisplay"]
    assert evidence["probeOrigin"] == "selected_edge"
    assert evidence["validationScope"] == "edge-local ingress route"
    assert evidence["externalIngressVerified"] is False
    assert evidence["listenerOrigin"] == ""
    assert "private-key" not in str(body).lower()
    assert "Bearer sensitive" not in str(body)
    assert "barragan-app" not in str(body)

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    channel = operations["inboundChannels"][0]
    assert channel["validationProfile"]["type"] == "tcp-send-receive"
    assert channel["validationProfile"]["expectedResponse"] == "hola ff10"
    assert channel["status"] == "Validated"
    assert channel["validation"]["profileType"] == "tcp-send-receive"
    assert channel["validation"]["profileLabel"] == "Raw HTTP over TCP"
    assert channel["validation"]["expectedResponse"] == "hola ff10"
    assert "hola ff10" in channel["validation"]["observedResponse"]
    assert "HTTP/1.1" not in channel["validation"]["observedResponse"]
    assert channel["validation"]["probeOrigin"] == "selected_edge"
    assert channel["validation"]["externalIngressVerified"] is False


def test_inbound_channel_validate_udp_send_receive_profile_records_evidence(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        playbook = (cwd / "ansible" / "validate_inbound_channel.yml").read_text(encoding="utf-8")
        manifest = (cwd / "MANIFEST.json").read_text(encoding="utf-8")
        assert "Start temporary inbound validation listener" not in playbook
        assert "Send UDP validation probe from selected edge through inbound route" in playbook
        assert "hosts: selected_edge" in playbook
        assert "hosts: localhost" not in playbook
        assert "connection: local" not in playbook
        assert "127.0.0.1" in playbook
        assert '"profileType": "udp-send-receive"' in manifest
        assert '"expectedResponse": "FF0000"' in manifest
        return subprocess.CompletedProcess(command, 0, stdout="FF0000\n", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "udp-primary",
                    "domain": "udp.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "Synthetic UDP",
                    "internalPort": "5353",
                    "purpose": "UDP validation contract",
                    "status": "Pending Validation",
                    "validationProfile": {
                        "type": "udp-send-receive",
                        "label": "UDP send/expect",
                        "requestText": "PING",
                        "expectedResponse": "FF0000",
                    },
                }
            ]
        },
    )

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/udp-primary/validate",
        json={"confirmation": "validate-inbound-udp-primary", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Validated"
    assert len(calls) == 1
    evidence = body["job"]["events"][-1]["data"]["validationEvidence"]
    assert evidence["profileType"] == "udp-send-receive"
    assert evidence["expectedResponse"] == "FF0000"
    assert evidence["observedResponse"] == "Matched expected response text: FF0000"
    assert "nc -u -w 5 127.0.0.1 443" in evidence["probeShellDisplay"]
    assert evidence["probeOrigin"] == "selected_edge"
    assert evidence["externalIngressVerified"] is False

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    channel = operations["inboundChannels"][0]
    assert channel["validationProfile"]["type"] == "udp-send-receive"
    assert channel["validation"]["profileType"] == "udp-send-receive"
    assert channel["validation"]["observedResponse"] == "Matched expected response text: FF0000"


def test_inbound_channel_validate_route_records_failure_without_claiming_validated(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, stdout="wrong-marker\n", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)

    response = client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/validate",
        json={"confirmation": "validate-inbound-c2-primary"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Validation Failed"
    assert body["job"]["status"] == "failed"
    evidence = body["job"]["events"][-1]["data"]["validationEvidence"]
    assert evidence["expectedMarker"] == "barragan-inbound-c2-primary"
    assert evidence["status"] == "Validation Failed"

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    assert operations["inboundChannels"][0]["status"] == "Validation Failed"
    assert operations["inboundChannels"][0]["validation"]["status"] == "Validation Failed"


def test_inbound_channel_remove_requires_confirmation_for_applied_channel(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")

    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, stdout="applied", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")
    _stub_provider_ingress_sync(monkeypatch)

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply",
        json={"confirmation": "apply-inbound-c2-primary"},
    )

    response = client.delete(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary",
        json={"confirmation": "wrong"},
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be remove-inbound-c2-primary"]
    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "inbound_channel_remove" and job.input.get("engagementId") == engagement_id
        ]
    assert jobs == []


def test_inbound_channel_remove_deconfigures_one_channel_and_preserves_siblings(client, tmp_path, monkeypatch):
    ansible_playbook = _make_executable(tmp_path, "ansible-playbook")
    calls = []

    def runner(command, cwd):
        calls.append((command, cwd))
        if command[-1] == "ansible/remove_inbound_channel.yml":
            playbook = (cwd / "ansible" / "remove_inbound_channel.yml").read_text(encoding="utf-8")
            assert "/etc/nginx/streams/barragan-c2-primary-edge-443.conf" in playbook
            assert "/etc/nginx/streams/barragan-c2-primary-middle-443.conf" in playbook
            assert "/etc/nginx/streams/barragan-c2-primary-proxy-443.conf" in playbook
            assert "source_arg='-s {{ barragan_edge_ip }}'" in playbook
            assert "source_arg='-s {{ barragan_middle_ip }}'" in playbook
            assert "comment=\"barragan-inbound-{{ barragan_channel_id }}-${rule_role}\"" in playbook
            assert "src: /tmp/barragan-keys/zy01-sketch" not in playbook
            assert "/opt/ssh-proxy/keys/zy01-sketch" not in playbook
            assert "ufw delete allow proto tcp" not in playbook
            assert "ufw status numbered" in playbook
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")

    monkeypatch.setenv("ANSIBLE_PLAYBOOK_BIN", str(ansible_playbook))
    monkeypatch.setattr("app.services.inbound_channel_apply._run_command", runner)
    monkeypatch.setattr("app.services.inbound_channel_apply._start_background_task", lambda task: task())
    monkeypatch.setattr("app.services.inbound_channel_apply.DEFAULT_WORKSPACE_ROOT", tmp_path / "inbound-workspaces")
    _stub_provider_ingress_sync(monkeypatch)

    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_inbound_channel(client, engagement_id)
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": "7443",
                    "purpose": "C2 ingress",
                    "status": "Not Ready",
                },
                {
                    "channelId": "web-secondary",
                    "domain": "web.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "8443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "proxy01-zy01",
                    "service": "OpenResty",
                    "internalPort": "8001",
                    "purpose": "Secondary ingress",
                    "status": "Not Ready",
                },
            ],
        },
    )
    client.post(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary/apply",
        json={"confirmation": "apply-inbound-c2-primary"},
    )

    response = client.delete(
        f"/api/engagements/{engagement_id}/inbound-channels/c2-primary",
        json={"confirmation": "remove-inbound-c2-primary", "requestedBy": "operator"},
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "Removed"
    assert body["job"]["action"] == "inbound_channel_remove"
    assert body["job"]["status"] == "succeeded"
    assert calls[-1][0] == [
        str(ansible_playbook),
        "-i",
        "ansible/inventory.ini",
        "ansible/remove_inbound_channel.yml",
    ]
    updated_channels = body["job"]["events"][-1]["data"]["inboundChannels"]
    assert [channel["channelId"] for channel in updated_channels] == ["c2-primary", "web-secondary"]
    assert updated_channels[0]["status"] == "Removed"
    assert updated_channels[1]["status"] == "Not Ready"

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]
    assert [channel["channelId"] for channel in operations["inboundChannels"]] == ["c2-primary", "web-secondary"]
    assert operations["inboundChannels"][0]["status"] == "Removed"
    assert operations["inboundChannels"][1]["status"] == "Not Ready"


def test_engagement_operations_patch_preserves_compact_outbound_metadata_and_drops_secret_fields(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    patch_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "outboundChannels": [
                {
                    "chainId": "chain-1",
                    "proxy": "proxy01",
                    "middle": "middle-zy01",
                    "edge": "edge-zy01",
                    "port": "3333",
                    "region": "us-sea",
                    "provider": "linode",
                    "domain": "chain-1",
                    "purpose": "Sketch egress profile chain-1",
                    "status": "Pending Proxy Configuration",
                    "profileName": "chain-1",
                    "publicationPath": "/opt/proxy01/chain-1-socks5.conf",
                    "apiToken": "must-not-persist",
                    "providerToken": "must-not-persist",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nmust-not-persist\n-----END OPENSSH PRIVATE KEY-----",
                    "validation": {
                        "origin": "homebase",
                        "command": ["curl", "-sS", "--connect-timeout", "10", "-x", "socks5h://proxy01:3333", "https://ipv4.icanhazip.com"],
                        "shellDisplay": "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
                        "expectedPublicIp": "203.0.113.20",
                        "secret": "must-not-persist",
                        "providerToken": "must-not-persist",
                    },
                    "artifactTargets": {
                        "homebaseProxychains": "/opt/proxy01/chain-1-socks5.conf",
                        "proxySshConfig": "/opt/ssh-proxy/config-3333",
                        "proxySystemdService": "/etc/systemd/system/ssh-proxy-3333.service",
                        "apiToken": "must-not-persist",
                        "privateKeyContent": "-----BEGIN OPENSSH PRIVATE KEY-----\nmust-not-persist\n-----END OPENSSH PRIVATE KEY-----",
                    },
                    "artifacts": {
                        "proxySshConfig": {
                            "target": "/opt/ssh-proxy/config-3333",
                            "content": "DynamicForward 0.0.0.0:3333\n",
                        },
                    },
                }
            ],
        },
    )
    channel = patch_response.get_json()["operations"]["outboundChannels"][0]

    assert patch_response.status_code == 200
    assert channel["status"] == "Pending Proxy Configuration"
    assert channel["profileName"] == "chain-1"
    assert channel["publicationPath"] == "/opt/proxy01/chain-1-socks5.conf"
    assert channel["validation"] == {
        "origin": "homebase",
        "shellDisplay": "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
        "expectedPublicIp": "203.0.113.20",
        "command": ["curl", "-sS", "--connect-timeout", "10", "-x", "socks5h://proxy01:3333", "https://ipv4.icanhazip.com"],
    }
    assert channel["artifactTargets"] == {
        "homebaseProxychains": "/opt/proxy01/chain-1-socks5.conf",
        "proxySshConfig": "/opt/ssh-proxy/config-3333",
        "proxySystemdService": "/etc/systemd/system/ssh-proxy-3333.service",
    }
    assert "artifacts" not in channel

    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "engagement_channels_update" and job.input.get("engagementId") == engagement_id
        ]
    assert len(jobs) == 1
    assert "must-not-persist" not in str(jobs[0].to_detail().to_dict())
    assert "DynamicForward" not in str(jobs[0].to_detail().to_dict())


def test_engagement_operations_patch_empty_channel_arrays_do_not_create_placeholder_rows(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    patch_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "outboundChannels": [],
            "inboundChannels": [],
        },
    )
    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]

    assert patch_response.status_code == 200
    assert operations["outboundChannels"] == []
    assert operations["inboundChannels"] == []

    with client.application.storage_context():
        jobs = [
            job for job in SqlAlchemyJobRepository().list()
            if job.action == "engagement_channels_update" and job.input.get("engagementId") == engagement_id
        ]
    assert len(jobs) == 1
    assert jobs[0].events[0].data["outboundChannels"] == []
    assert jobs[0].events[0].data["inboundChannels"] == []


def test_engagement_operations_marks_core_rows_destroyed_after_verified_cleanup(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_core_lifecycle_job(
        client,
        engagement_id,
        [
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run finished",
                {
                    "connectionDetails": _pilot_connection_details("zy01"),
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                },
            ),
            JobEvent(
                2,
                "info",
                "cleanup verification completed",
                {"ok": True, "remainingCount": 0, "status": "verified_clean"},
            ),
            JobEvent(
                3,
                "info",
                "pilot Standard RTI teardown finished",
                {"mutationStatus": "destroyed", "finalCleanupStatus": "verified_clean"},
            ),
        ],
    )

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]

    assert operations["healthSummary"]["status"] == "destroyed"
    assert operations["healthSummary"]["hostCount"] == 3
    assert operations["healthSummary"]["activeHostCount"] == 0
    assert operations["coreInfrastructure"][0]["lifecycleState"] == "destroyed"
    assert operations["coreInfrastructure"][0]["lastKnown"] is True
    assert operations["coreInfrastructure"][0]["health"]["status"] == "destroyed"
    assert "last-known" in operations["coreInfrastructure"][0]["health"]["detail"]


def test_engagement_operations_marks_core_rows_attention_when_cleanup_not_verified(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_core_lifecycle_job(
        client,
        engagement_id,
        [
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run finished",
                {
                    "connectionDetails": _pilot_connection_details("zy01"),
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                },
            ),
            JobEvent(
                2,
                "error",
                "cleanup verification completed",
                {"ok": False, "remainingCount": 9, "status": "cleanup_not_verified"},
            ),
            JobEvent(
                3,
                "error",
                "pilot Standard RTI teardown finished",
                {"mutationStatus": "destroyed", "finalCleanupStatus": "cleanup_not_verified"},
            ),
        ],
    )

    operations = client.get(f"/api/engagements/{engagement_id}/operations").get_json()["operations"]

    assert operations["healthSummary"]["status"] == "attention"
    assert operations["healthSummary"]["activeHostCount"] == 0
    assert operations["coreInfrastructure"][0]["lifecycleState"] == "cleanup_not_verified"
    assert operations["coreInfrastructure"][0]["lastKnown"] is True
    assert operations["coreInfrastructure"][0]["health"]["status"] == "attention"
    assert "did not prove" in operations["coreInfrastructure"][0]["health"]["detail"]


def test_dashboard_summarizes_active_recent_teardown_and_archive_activity(client):
    active_response = client.post("/api/engagements", json={"name": "AA01", "owner": "example_operator"})
    destroyed_response = client.post("/api/engagements", json={"name": "ZZ01", "owner": "example_operator"})
    retired_response = client.post("/api/engagements", json={"name": "OLD01", "owner": "example_operator"})
    active_id = active_response.get_json()["engagement"]["id"]
    destroyed_id = destroyed_response.get_json()["engagement"]["id"]
    retired_id = retired_response.get_json()["engagement"]["id"]
    _seed_core_lifecycle_job(
        client,
        active_id,
        [
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run finished",
                {
                    "connectionDetails": _pilot_connection_details("aa01"),
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                },
            )
        ],
    )
    _seed_core_lifecycle_job(
        client,
        destroyed_id,
        [
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run finished",
                {
                    "connectionDetails": _pilot_connection_details("zz01"),
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                },
            ),
            JobEvent(
                2,
                "info",
                "pilot Standard RTI teardown finished",
                {"mutationStatus": "destroyed", "finalCleanupStatus": "verified_clean"},
            ),
        ],
    )
    _seed_core_lifecycle_job(
        client,
        retired_id,
        [
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run finished",
                {
                    "connectionDetails": _pilot_connection_details("old01"),
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                },
            ),
            JobEvent(
                2,
                "info",
                "pilot Standard RTI teardown finished",
                {"mutationStatus": "destroyed", "finalCleanupStatus": "verified_clean"},
            ),
        ],
    )
    retire_response = client.delete(f"/api/engagements/{retired_id}")
    assert retire_response.status_code == 200

    response = client.get("/api/dashboard")
    body = response.get_json()["dashboard"]

    assert response.status_code == 200
    assert body["summary"]["activeInfrastructure"] == 1
    assert body["summary"]["destroyed"] == 0
    assert body["summary"]["lastKnown"] == 0
    assert body["summary"]["recentTeardowns"] == 1
    assert body["summary"]["recentArchives"] == 1
    active_row = next(row for row in body["inventory"] if row["engagementId"] == active_id)
    assert destroyed_id not in {row["engagementId"] for row in body["inventory"]}
    assert retired_id not in {row["engagementId"] for row in body["inventory"]}
    assert active_row["lifecycleState"] == "active"
    assert active_row["activeCoreHostCount"] == 3
    assert active_row["providers"] == ["oci"]
    assert active_row["regions"] == ["us-sanjose-1"]
    activity = body["engagementOverview"]
    active_activity = next(row for row in activity["active"] if row["engagementId"] == active_id)
    ended_activity = next(row for row in activity["recentlyEnded"] if row["engagementId"] == destroyed_id)
    archived_activity = next(row for row in activity["recentlyArchived"] if row["engagementId"] == retired_id)
    assert active_activity["activeDurationLabel"]
    assert active_activity["healthStatus"] == "healthy"
    assert ended_activity["endedAt"]
    assert archived_activity["archivedAt"]
    assert body["systemHealth"]["api"]["status"] == "ok"
    assert body["systemHealth"]["database"]["status"] == "ok"
    assert body["systemHealth"]["disk"]["status"] in {"ok", "warning", "critical"}
    assert body["systemHealth"]["providers"]["status"] == "not checked"
    assert body["reconciliation"]["status"] == "local-records"

    all_engagements = client.get("/api/engagements?scope=all").get_json()["engagements"]
    destroyed_engagement = next(engagement for engagement in all_engagements if engagement["id"] == destroyed_id)
    retired_engagement = next(engagement for engagement in all_engagements if engagement["id"] == retired_id)
    assert destroyed_engagement["status"] != "retired"
    assert retired_engagement["status"] == "retired"


def test_dashboard_inventory_surfaces_cleanup_not_verified_as_attention(client):
    create_response = client.post("/api/engagements", json={"name": "BAD01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    _seed_core_lifecycle_job(
        client,
        engagement_id,
        [
            JobEvent(
                1,
                "info",
                "pilot Standard RTI run finished",
                {
                    "connectionDetails": _pilot_connection_details("bad01"),
                    "mutationStatus": "deployed",
                    "finalCleanupStatus": "pending_operator_teardown",
                },
            ),
            JobEvent(
                2,
                "error",
                "pilot Standard RTI teardown finished",
                {"mutationStatus": "destroyed", "finalCleanupStatus": "cleanup_not_verified", "remainingCount": 4},
            ),
        ],
    )

    body = client.get("/api/dashboard").get_json()["dashboard"]
    row = next(row for row in body["inventory"] if row["engagementId"] == engagement_id)

    assert body["summary"]["attention"] == 1
    assert row["lifecycleState"] == "cleanup_not_verified"
    assert row["healthStatus"] == "attention"
    assert row["attention"] is True


def test_dashboard_default_does_not_perform_live_provider_discovery(client, monkeypatch):
    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: (_ for _ in ()).throw(AssertionError("live provider discovery should be explicit")),
    )

    response = client.get("/api/dashboard")
    body = response.get_json()["dashboard"]

    assert response.status_code == 200
    assert body["summary"]["orphanCandidates"] == 0
    assert body["reconciliation"]["status"] == "local-records"


def test_engagement_operations_default_does_not_perform_live_provider_discovery(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: (_ for _ in ()).throw(AssertionError("live provider discovery should be explicit")),
    )

    response = client.get(f"/api/engagements/{engagement_id}/operations")
    operations = response.get_json()["operations"]

    assert response.status_code == 200
    assert operations["providerFindings"] == []


def test_dashboard_inventory_surfaces_provider_orphan_candidates(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..orphan",
                "name": "homebase-or01",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementId": engagement_id,
                "engagementName": "OR01",
                "metadata": {"barraganOwned": True},
                "source": "provider_inventory",
            }
        ],
    )

    _inject_dashboard_discovery_evidence(monkeypatch)

    body = client.get("/api/dashboard?live=1").get_json()["dashboard"]

    assert body["summary"]["orphanCandidates"] == 1
    assert body["reconciliation"]["status"] == "provider-reconciled"
    candidate = body["orphanCandidates"][0]
    assert candidate["engagementId"] == engagement_id
    assert candidate["provider"] == "oci"
    assert candidate["resourceType"] == "compute_instance"
    assert candidate["lifecycleState"] == "RUNNING"
    assert "no active local deployment state" in candidate["reason"]


def test_dashboard_unmanaged_rti_finding_does_not_offer_or_accept_teardown(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    calls = []

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..manual",
                "name": "homebase-or01",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementId": engagement_id,
                "engagementName": "OR01",
                "metadata": {},
                "source": "provider_inventory",
            }
        ],
    )
    monkeypatch.setattr("app.services.provider_orphan_recovery._run_oci_command", lambda command: calls.append(command))

    _inject_dashboard_discovery_evidence(monkeypatch)

    dashboard_body = client.get("/api/dashboard?live=1").get_json()["dashboard"]
    candidate = dashboard_body["orphanCandidates"][0]
    assert candidate["classification"] == "unmanaged_rti"
    assert candidate["actions"] == ["track", "mark_destroyed"]
    assert "does not carry Barragan ownership tags" in candidate["reason"]

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "oci:compute_instance:ocid1.instance.oc1..manual",
            "action": "tear_down",
            "requestedBy": "operator",
        },
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["tear_down is not available for this provider reconciliation finding"]
    assert calls == []


def test_engagement_operations_shows_provider_findings_for_matching_engagement(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..manual",
                "name": "homebase-or01",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementId": engagement_id,
                "engagementName": "OR01",
                "metadata": {},
                "source": "provider_inventory",
            }
        ],
    )

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]

    assert operations["providerFindings"][0]["candidateId"] == "oci:compute_instance:ocid1.instance.oc1..manual"
    assert operations["providerFindings"][0]["classification"] == "unmanaged_rti"
    assert operations["providerFindings"][0]["actions"] == ["track", "mark_destroyed"]
    assert "does not carry Barragan ownership tags" in operations["providerFindings"][0]["reason"]


def test_engagement_retirement_blocks_persisted_owned_active_resource(client):
    from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository, StoredProviderResourceRecord
    engagement_id = client.post("/api/engagements", json={"name": "OWN01", "owner": "operator"}).get_json()["engagement"]["id"]
    with client.application.storage_context():
        SqlAlchemyProviderResourceRepository().save(StoredProviderResourceRecord(
            id="resource-owned", engagement_id=engagement_id, engagement_name="OWN01", provider="linode",
            resource_type="instance", resource_id="12345", name="edge-owned", region="us-sea",
            lifecycle_state="running", status="active", source="barragan", metadata={"barraganOwned": True},
            adoption_job_id="", adopted_at="2026-10-28T12:00:00Z", updated_at="2026-10-28T12:00:00Z",
        ))
    response = client.delete(f"/api/engagements/{engagement_id}")
    assert response.status_code == 409
    body = response.get_json()
    assert "active infrastructure" in body["error"].lower()
    assert any(row["kind"] == "owned_provider_resource" for row in body["activeInfrastructure"]["lifecycle"]["evidence"])
    assert client.get(f"/api/engagements/{engagement_id}").get_json()["engagement"]["status"] == "draft"


def test_engagement_retirement_does_not_discover_unmanaged_provider_resources(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR02", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    discovery_calls = []

    def discover():
        discovery_calls.append(True)
        return [
            {
                "provider": "linode",
                "resourceType": "instance",
                "resourceId": "12345",
                "name": "edge-OR02-us-sea-proxy01-sea-01",
                "region": "us-sea",
                "lifecycleState": "running",
                "engagementId": engagement_id,
                "engagementName": "OR02",
                "source": "provider_inventory",
            }
        ]

    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", discover)
    response = client.delete(f"/api/engagements/{engagement_id}")
    body = response.get_json()

    assert response.status_code == 200
    assert body["engagement"]["status"] == "retired"
    assert discovery_calls == []
    with client.application.storage_context():
        assert SqlAlchemyJobRepository().list_for_engagement(engagement_id) == []


def test_dashboard_orphan_recovery_tracks_provider_resource_into_durable_records(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR03", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..orphan",
                "name": "homebase-or03",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementId": engagement_id,
                "engagementName": "OR03",
                "metadata": {"publicIps": ["203.0.113.30"]},
                "source": "provider_inventory",
            }
        ],
    )

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "oci:compute_instance:ocid1.instance.oc1..orphan",
            "action": "track",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["status"] == "tracked"
    assert body["candidate"]["engagementId"] == engagement_id
    assert body["job"]["action"] == "provider_orphan_track"
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["targetType"] == "provider_orphan"
    provider_record = body["job"]["events"][0]["data"]["providerRecord"]
    assert provider_record["status"] == "tracked"
    assert provider_record["metadata"]["trackingMode"] == "visibility_only"
    assert provider_record["metadata"]["barraganOwned"] is False

    _inject_dashboard_discovery_evidence(monkeypatch)

    dashboard = client.get("/api/dashboard?live=1").get_json()["dashboard"]
    assert dashboard["summary"]["orphanCandidates"] == 0

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    tracked_homebase = next(row for row in operations["coreInfrastructure"] if row["hostname"] == "homebase-or03")
    assert tracked_homebase["providerResourceId"] == "ocid1.instance.oc1..orphan"
    assert tracked_homebase["lifecycleState"] == "tracked"
    assert tracked_homebase["health"]["source"] == "oci api"
    assert tracked_homebase["health"]["status"] == "present"
    assert tracked_homebase["health"]["stale"] is False

    delete_response = client.delete(f"/api/engagements/{engagement_id}")
    delete_body = delete_response.get_json()
    assert delete_response.status_code == 200
    assert delete_body["engagement"]["status"] == "retired"
    with client.application.storage_context():
        from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
        retained = SqlAlchemyProviderResourceRepository().list_for_engagement(engagement_id)
        assert len(retained) == 1
        assert retained[0].metadata["barraganOwned"] is False
        assert retained[0].status == "tracked"


def test_engagement_operations_marks_tracked_provider_record_attention_when_missing_from_provider(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR03", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    provider_resources = [
        {
            "provider": "linode",
            "resourceType": "instance",
            "resourceId": "12345",
            "name": "edge-OR03-us-sea-proxy01-sea-01",
            "region": "us-sea",
            "lifecycleState": "running",
            "engagementId": engagement_id,
            "engagementName": "OR03",
            "metadata": {"publicIps": ["203.0.113.45"]},
            "source": "linode_api",
        }
    ]
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", lambda: provider_resources)

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "linode:instance:12345",
            "action": "track",
            "requestedBy": "operator",
        },
    )
    assert response.status_code == 201

    provider_resources[:] = [
        {
            "provider": "linode",
            "resourceType": "instance",
            "resourceId": "99999",
            "name": "edge-OR03-us-sea-proxy01-sea-99",
            "region": "us-sea",
            "lifecycleState": "running",
            "engagementName": "OR03",
            "source": "linode_api",
        }
    ]

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    tracked_edge = next(row for row in operations["sketchInfrastructure"] if row["hostname"] == "edge-OR03-us-sea-proxy01-sea-01")

    assert tracked_edge["status"] == "attention"
    assert tracked_edge["health"]["source"] == "linode api"
    assert "did not report" in tracked_edge["health"]["detail"]
    assert operations["providerFindings"][0]["resourceId"] == "99999"


def test_engagement_operations_hides_inspector_resources_from_sketch_infrastructure(client, monkeypatch):
    create_response = client.post("/api/engagements", json={"name": "OR14", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]
    provider_resources = [
        {
            "provider": "linode",
            "resourceType": "instance",
            "resourceId": "12345",
            "name": "edge-OR14-us-sea-proxy01-sea-01",
            "region": "us-sea",
            "lifecycleState": "running",
            "engagementId": engagement_id,
            "engagementName": "OR14",
            "metadata": {"publicIps": ["203.0.113.45"]},
            "source": "linode_api",
        },
        {
            "provider": "linode",
            "resourceType": "inspector_instance",
            "resourceId": "67890",
            "name": "inspector-or14-jobabc",
            "region": "us-sea",
            "lifecycleState": "running",
            "engagementId": engagement_id,
            "engagementName": "OR14",
            "metadata": {"role": "inspector", "publicIps": ["203.0.113.46"]},
            "source": "inspector",
        },
    ]
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", lambda: provider_resources)

    for candidate_id in ("linode:instance:12345", "linode:inspector_instance:67890"):
        response = client.post(
            "/api/dashboard/orphan-candidates/actions",
            json={
                "candidateId": candidate_id,
                "action": "track",
                "requestedBy": "operator",
            },
        )
        assert response.status_code == 201

    operations = client.get(f"/api/engagements/{engagement_id}/operations?live=1").get_json()["operations"]
    hostnames = {row["hostname"] for row in operations["sketchInfrastructure"]}

    assert "edge-OR14-us-sea-proxy01-sea-01" in hostnames
    assert "inspector-or14-jobabc" not in hostnames


def test_dashboard_orphan_recovery_records_mark_destroyed_note_without_suppressing_candidate(client, monkeypatch):
    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "linode",
                "resourceType": "instance",
                "resourceId": "12345",
                "name": "edge-OR04-us-sea-proxy01-sea-01",
                "region": "us-sea",
                "lifecycleState": "running",
                "engagementName": "OR04",
                "metadata": {"barraganOwned": True},
                "source": "linode_api",
            }
        ],
    )

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "linode:instance:12345",
            "action": "mark_destroyed",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["status"] == "recorded"
    assert body["job"]["action"] == "provider_orphan_mark_destroyed_note"
    assert body["job"]["events"][0]["data"]["suppressesProviderFinding"] is False

    _inject_dashboard_discovery_evidence(monkeypatch)

    dashboard = client.get("/api/dashboard?live=1").get_json()["dashboard"]
    assert dashboard["summary"]["orphanCandidates"] == 1


def test_dashboard_orphan_recovery_teardown_preview_reports_confirmation(client, monkeypatch):
    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "digitalocean",
                "resourceType": "droplet",
                "resourceId": "67890",
                "name": "edge-OR05-sfo3-proxy02-sfo3-01",
                "region": "sfo3",
                "lifecycleState": "active",
                "engagementName": "OR05",
                "metadata": {"barraganOwned": True},
                "source": "digitalocean_api",
            }
        ],
    )

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "digitalocean:droplet:67890",
            "action": "tear_down",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 201
    assert body["status"] == "planned"
    assert body["confirmationToken"] == "tear-down-digitalocean-droplet-67890"
    assert body["job"]["action"] == "provider_orphan_teardown_plan"
    assert body["job"]["events"][0]["data"]["supportedLiveMutation"] is True


def test_dashboard_orphan_recovery_teardown_requires_confirmation_for_mutation(client, monkeypatch):
    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "digitalocean",
                "resourceType": "droplet",
                "resourceId": "67890",
                "name": "edge-OR06-sfo3-proxy02-sfo3-01",
                "region": "sfo3",
                "lifecycleState": "active",
                "engagementName": "OR06",
                "metadata": {"barraganOwned": True},
                "source": "digitalocean_api",
            }
        ],
    )

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "digitalocean:droplet:67890",
            "action": "tear_down",
            "mutation": True,
            "confirmation": "wrong",
            "requestedBy": "operator",
        },
    )

    assert response.status_code == 400
    assert response.get_json()["errors"] == ["confirmation must be tear-down-digitalocean-droplet-67890"]


def test_dashboard_orphan_recovery_teardown_mutation_requests_provider_delete(client, monkeypatch):
    calls = []

    class FakeTransport:
        def request(self, base_url, method, path, token):
            calls.append((base_url, method, path, token))
            return {}

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "digitalocean",
                "resourceType": "droplet",
                "resourceId": "67890",
                "name": "edge-OR07-sfo3-proxy02-sfo3-01",
                "region": "sfo3",
                "lifecycleState": "active",
                "engagementName": "OR07",
                "metadata": {"barraganOwned": True},
                "source": "digitalocean_api",
            }
        ],
    )
    monkeypatch.setattr("app.services.provider_orphan_recovery.provider_reconciliation._provider_token", lambda provider: "test-token")
    monkeypatch.setattr("app.services.provider_orphan_recovery.UrllibProviderCatalogTransport", lambda: FakeTransport())

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "digitalocean:droplet:67890",
            "action": "tear_down",
            "mutation": True,
            "confirmation": "tear-down-digitalocean-droplet-67890",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["status"] == "succeeded"
    assert body["job"]["action"] == "provider_orphan_teardown"
    assert calls == [("https://api.digitalocean.com/v2", "DELETE", "/droplets/67890", "test-token")]


def test_dashboard_orphan_recovery_oci_compute_teardown_requests_scoped_cli_terminate(client, monkeypatch):
    calls = []

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..abc",
                "name": "homebase-OR08",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementName": "OR08",
                "metadata": {"barraganOwned": True, "compartmentId": BARRAGAN_TESTING_COMPARTMENT_ID},
                "source": "oci_api",
            }
        ],
    )
    monkeypatch.setattr(
        "app.services.provider_orphan_recovery.resolve_oci_cli",
        lambda: type("Resolution", (), {"ok": True, "command": "oci", "error": None})(),
    )

    def fake_run(command):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr("app.services.provider_orphan_recovery._run_oci_command", fake_run)

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "oci:compute_instance:ocid1.instance.oc1..abc",
            "action": "tear_down",
            "mutation": True,
            "confirmation": "tear-down-oci-compute-instance-ocid1-instance-oc1-abc",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["events"][1]["message"] == "OCI compute instance terminate requested"
    assert body["job"]["events"][2]["message"] == "OCI orphan teardown verification completed"
    assert calls == [
        [
            "oci",
            "--auth",
            "instance_principal",
            "--region",
            "us-sanjose-1",
            "compute",
            "instance",
            "terminate",
            "--instance-id",
            "ocid1.instance.oc1..abc",
            "--force",
        ],
        [
            "oci",
            "--auth",
            "instance_principal",
            "--region",
            "us-sanjose-1",
            "compute",
            "instance",
            "list",
            "--compartment-id",
            BARRAGAN_TESTING_COMPARTMENT_ID,
            "--all",
            "--output",
            "json",
        ],
    ]


def test_dashboard_orphan_recovery_oci_subnet_teardown_requests_scoped_cli_delete_and_verifies(client, monkeypatch):
    calls = []

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "subnet",
                "resourceId": "ocid1.subnet.oc1..abc",
                "name": "or10-proxy-subnet",
                "region": "us-sanjose-1",
                "lifecycleState": "AVAILABLE",
                "engagementName": "OR10",
                "metadata": {
                    "barraganOwned": True,
                    "compartmentId": BARRAGAN_TESTING_COMPARTMENT_ID,
                    "vcnId": "ocid1.vcn.oc1..or10",
                },
                "source": "oci_api",
            }
        ],
    )
    monkeypatch.setattr(
        "app.services.provider_orphan_recovery.resolve_oci_cli",
        lambda: type("Resolution", (), {"ok": True, "command": "oci", "error": None})(),
    )

    def fake_run(command):
        calls.append(command)
        if "list" in command:
            return subprocess.CompletedProcess(command, 0, '{"data": []}', "")
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr("app.services.provider_orphan_recovery._run_oci_command", fake_run)

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "oci:subnet:ocid1.subnet.oc1..abc",
            "action": "tear_down",
            "mutation": True,
            "confirmation": "tear-down-oci-subnet-ocid1-subnet-oc1-abc",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["events"][1]["message"] == "OCI subnet delete requested"
    assert body["job"]["events"][2]["message"] == "OCI orphan teardown verification completed"
    assert calls == [
        [
            "oci",
            "--auth",
            "instance_principal",
            "--region",
            "us-sanjose-1",
            "network",
            "subnet",
            "delete",
            "--subnet-id",
            "ocid1.subnet.oc1..abc",
            "--force",
        ],
        [
            "oci",
            "--auth",
            "instance_principal",
            "--region",
            "us-sanjose-1",
            "network",
            "subnet",
            "list",
            "--compartment-id",
            BARRAGAN_TESTING_COMPARTMENT_ID,
            "--all",
            "--output",
            "json",
        ],
    ]


def test_dashboard_orphan_recovery_oci_vcn_teardown_orders_grouped_core_resources(client, monkeypatch):
    calls = []
    client.post("/api/engagements", json={"name": "OR10", "owner": "example_operator"})

    common = {
        "provider": "oci",
        "region": "us-sanjose-1",
        "engagementName": "OR10",
        "metadata": {
            "barraganOwned": True,
            "compartmentId": BARRAGAN_TESTING_COMPARTMENT_ID,
            "vcnId": "ocid1.vcn.oc1..or10",
        },
        "source": "oci_api",
    }
    provider_resources = [
        {
            **common,
            "resourceType": "security_list",
            "resourceId": "ocid1.securitylist.oc1..or10",
            "name": "or10-security",
            "lifecycleState": "AVAILABLE",
        },
        {
            **common,
            "resourceType": "internet_gateway",
            "resourceId": "ocid1.internetgateway.oc1..or10",
            "name": "or10-gateway",
            "lifecycleState": "AVAILABLE",
        },
        {
            **common,
            "resourceType": "route_table",
            "resourceId": "ocid1.routetable.oc1..or10",
            "name": "or10-route",
            "lifecycleState": "AVAILABLE",
        },
        {
            **common,
            "resourceType": "subnet",
            "resourceId": "ocid1.subnet.oc1..or10",
            "name": "or10-proxy-subnet",
            "lifecycleState": "AVAILABLE",
        },
        {
            **common,
            "resourceType": "compute_instance",
            "resourceId": "ocid1.instance.oc1..or10",
            "name": "homebase-or10",
            "lifecycleState": "RUNNING",
        },
        {
            **common,
            "resourceType": "vcn",
            "resourceId": "ocid1.vcn.oc1..or10",
            "name": "or10-vcn",
            "lifecycleState": "AVAILABLE",
        },
    ]
    monkeypatch.setattr("app.services.provider_reconciliation.discover_provider_resources", lambda: provider_resources)
    monkeypatch.setattr(
        "app.services.provider_orphan_recovery.resolve_oci_cli",
        lambda: type("Resolution", (), {"ok": True, "command": "oci", "error": None})(),
    )

    def fake_run(command):
        calls.append(command)
        if "list" in command:
            return subprocess.CompletedProcess(command, 0, '{"data": []}', "")
        return subprocess.CompletedProcess(command, 0, "{}", "")

    monkeypatch.setattr("app.services.provider_orphan_recovery._run_oci_command", fake_run)

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "oci:vcn:ocid1.vcn.oc1..or10",
            "action": "tear_down",
            "mutation": True,
            "confirmation": "tear-down-oci-vcn-ocid1-vcn-oc1-or10",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    delete_calls = [call for call in calls if "delete" in call or "terminate" in call]
    assert response.status_code == 202
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["events"][1]["message"] == "OCI VCN recovery teardown requested for grouped core resources"
    assert body["job"]["events"][1]["data"]["resourceCount"] == 6
    assert [call[5:8] for call in delete_calls] == [
        ["compute", "instance", "terminate"],
        ["network", "subnet", "delete"],
        ["network", "route-table", "delete"],
        ["network", "internet-gateway", "delete"],
        ["network", "security-list", "delete"],
        ["network", "vcn", "delete"],
    ]


def test_dashboard_orphan_recovery_oci_teardown_rejects_non_testing_compartment(client, monkeypatch):
    calls = []

    monkeypatch.setattr(
        "app.services.provider_reconciliation.discover_provider_resources",
        lambda: [
            {
                "provider": "oci",
                "resourceType": "compute_instance",
                "resourceId": "ocid1.instance.oc1..parent",
                "name": "homebase-OR09",
                "region": "us-sanjose-1",
                "lifecycleState": "RUNNING",
                "engagementName": "OR09",
                "metadata": {"barraganOwned": True, "compartmentId": BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID},
                "source": "oci_api",
            }
        ],
    )
    monkeypatch.setattr(
        "app.services.provider_orphan_recovery.resolve_oci_cli",
        lambda: type("Resolution", (), {"ok": True, "command": "oci", "error": None})(),
    )
    monkeypatch.setattr("app.services.provider_orphan_recovery._run_oci_command", lambda command: calls.append(command))

    response = client.post(
        "/api/dashboard/orphan-candidates/actions",
        json={
            "candidateId": "oci:compute_instance:ocid1.instance.oc1..parent",
            "action": "tear_down",
            "mutation": True,
            "confirmation": "tear-down-oci-compute-instance-ocid1-instance-oc1-parent",
            "requestedBy": "operator",
        },
    )
    body = response.get_json()

    assert response.status_code == 202
    assert body["job"]["status"] == "failed"
    assert "barragan-testing" in body["job"]["events"][-1]["data"]["detail"]
    assert calls == []


def test_engagement_operations_patch_preserves_omitted_channel_direction(client):
    create_response = client.post("/api/engagements", json={"name": "ZY01", "owner": "example_operator"})
    engagement_id = create_response.get_json()["engagement"]["id"]

    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "outboundChannels": [
                {
                    "chainId": "chain-1",
                    "proxy": "proxy01-zy01",
                    "middle": "middle01-zy01",
                    "edge": "edge-zy01-us-sea-01",
                    "port": "3333",
                    "domain": "egress.example.invalid",
                }
            ],
            "inboundChannels": [
                {
                    "channelId": "c2-ingress",
                    "domain": "c2.example.invalid",
                    "externalPort": "443",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": "7443",
                }
            ],
        },
    )

    patch_response = client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "backflips-ingress",
                    "domain": "bf.example.invalid",
                    "externalPort": "443",
                    "terminatesOn": "proxy01-zy01",
                    "service": "SSH Backflips",
                    "internalPort": "8001",
                }
            ],
        },
    )
    operations = patch_response.get_json()["operations"]

    assert patch_response.status_code == 200
    assert operations["outboundChannels"][0]["domain"] == "egress.example.invalid"
    assert operations["outboundChannels"][0]["proxy"] == "proxy01-zy01"
    assert operations["inboundChannels"][0]["domain"] == "bf.example.invalid"
    assert operations["inboundChannels"][0]["terminatesOn"] == "proxy01-zy01"


def test_create_engagement_endpoint_rejects_invalid_template_input(client):
    payload = valid_standard_rti_payload()
    payload["sketchChains"][0]["edgeProvider"] = "oci"

    response = client.post(
        "/api/engagements",
        json={
            "templateId": "standard-rti",
            "owner": "operator@example.invalid",
            "inputParameters": payload,
        },
    )
    body = response.get_json()

    assert response.status_code == 400
    assert "edgeProvider" in body["errors"][0]


def test_create_revision_endpoint_compiles_plan_only_revision(client):
    create_response = client.post(
        "/api/engagements",
        json={
            "templateId": "standard-rti",
            "owner": "operator@example.invalid",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]

    response = client.post(f"/api/engagements/{engagement_id}/revisions")
    body = response.get_json()

    assert response.status_code == 201
    assert body["revision"]["status"] == "compiled"
    assert body["revision"]["resolvedTopology"]["sketchChains"][0]["managementPath"][1] == "homebase"
    assert body["revision"]["validationGates"][0]["id"] == "core-topology"
    assert {gate["status"] for gate in body["revision"]["validationGates"]} == {"passed"}

    detail_response = client.get(f"/api/revisions/{body['revision']['id']}")
    assert detail_response.status_code == 200

    engagement_response = client.get(f"/api/engagements/{engagement_id}")
    engagement_body = engagement_response.get_json()
    assert engagement_response.status_code == 200
    assert engagement_body["engagement"]["status"] == "planned"
    assert engagement_body["engagement"]["activeRevision"] == body["revision"]["id"]


def test_render_revision_endpoint_writes_local_artifacts(client, tmp_path):
    create_response = client.post(
        "/api/engagements",
        json={
            "templateId": "standard-rti",
            "owner": "operator@example.invalid",
            "inputParameters": valid_standard_rti_payload(),
        },
    )
    engagement_id = create_response.get_json()["engagement"]["id"]
    revision_response = client.post(f"/api/engagements/{engagement_id}/revisions")
    revision_id = revision_response.get_json()["revision"]["id"]

    response = client.post(
        f"/api/revisions/{revision_id}/render",
        json={
            "renderDestination": str(tmp_path),
            "renderJobId": "job-api-render-test",
        },
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["renderResult"]["revisionId"] == revision_id
    assert body["renderResult"]["root"].startswith(str(tmp_path))
    assert len(body["renderResult"]["artifacts"]) >= 11
    assert (tmp_path / "engagements" / engagement_id / "revisions" / "r0001" / "manifest.yaml").exists()
    assert (tmp_path / "engagements" / engagement_id / "revisions" / "r0001" / "validation" / "gates.yaml").exists()


def test_jobs_endpoint_returns_recorded_job_runs(client):
    response = client.get("/api/jobs")
    body = response.get_json()

    assert response.status_code == 200
    assert body["jobs"][0]["status"] == "succeeded"


def test_job_detail_and_dry_run_execution(client):
    create_response = client.post(
        "/api/jobs",
        json={
            "action": "deploy_plan",
            "targetType": "revision",
            "targetId": "rev-test",
            "requestedBy": "operator@example.invalid",
            "input": {"mode": "dry_run"},
        },
    )
    job_id = create_response.get_json()["job"]["id"]

    run_response = client.post(f"/api/jobs/{job_id}/run")
    body = run_response.get_json()

    assert run_response.status_code == 200
    assert body["job"]["status"] == "succeeded"
    assert body["job"]["events"][0]["message"] == "job queued"


def test_plan_only_orchestrator_endpoint(client):
    response = client.post(
        "/api/orchestrator/standard-rti/plan",
        json={
            "engagementId": "eng-api-plan",
            "inputParameters": valid_standard_rti_payload(),
            "accessUsers": [
                {
                    "userId": "user-1",
                    "username": "alice",
                    "credentialRef": "secret://users/alice",
                    "privileges": ["view", "operate"],
                }
            ],
        },
    )
    body = response.get_json()

    assert response.status_code == 200
    assert body["plan"]["revision"]["status"] == "compiled"
    assert body["plan"]["revision"]["validationGates"][-1]["id"] == "plan-only-intent"
    assert body["plan"]["providerPlan"]["mode"] == "dry_run"


def valid_standard_rti_payload():
    return {
        "engagementName": "of02-dev",
        "proxyCount": 2,
        "elkEnabled": False,
        "sketchChains": [
            {
                "id": "chain-1",
                "assignedProxy": "proxy01",
                "middleProvider": "linode",
                "edgeProvider": "digitalocean",
            }
        ],
        "egressProfiles": [
            {
                "name": "default-sketch-egress",
                "sketchChainId": "chain-1",
                "listenerPort": 3333,
            }
        ],
        "ingressRoutes": [
            {
                "name": "default-ingress",
                "sketchChainId": "chain-1",
                "domain": "example.invalid",
            }
        ],
        "reverseChannels": [],
    }


def _pending_outbound_channel(
    engagement_name: str,
    chain_id: str,
    *,
    proxy: str = "proxy01",
    middle_ip: str = "203.0.113.20",
    edge_ip: str = "203.0.113.30",
):
    channel = derive_pending_outbound_channel_from_sketch_rows(
        engagement_name,
        chain_id,
        [
            {
                "chainId": chain_id,
                "hostname": f"middle-{engagement_name.lower()}-{chain_id}",
                "provider": "linode",
                "role": "middle",
                "publicIp": middle_ip,
                "region": "us-sea",
                "proxy": proxy,
                "status": "deployed",
            },
            {
                "chainId": chain_id,
                "hostname": f"edge-{engagement_name.lower()}-{chain_id}",
                "provider": "linode",
                "role": "edge",
                "publicIp": edge_ip,
                "region": "us-sea",
                "proxy": proxy,
                "status": "deployed",
            },
        ],
    )
    assert channel is not None
    return channel


def _pilot_connection_details(engagement_name: str):
    return [
        {
            "role": "homebase",
            "displayName": f"homebase-{engagement_name}",
            "sshAlias": f"homebase-{engagement_name}",
            "publicIp": "203.0.113.10",
            "privateIp": "192.168.0.10",
            "region": "us-sanjose-1",
            "sshUser": "user",
            "services": ["SSH", "RTI base layout"],
        },
        {
            "role": "proxy",
            "displayName": f"proxy01-{engagement_name}",
            "sshAlias": f"proxy01-{engagement_name}",
            "publicIp": "203.0.113.11",
            "privateIp": "192.168.2.11",
            "region": "us-sanjose-1",
            "sshUser": "user",
            "services": ["SSH", "RTI base layout"],
        },
        {
            "role": "proxy",
            "displayName": f"proxy02-{engagement_name}",
            "sshAlias": f"proxy02-{engagement_name}",
            "publicIp": "203.0.113.12",
            "privateIp": "192.168.2.12",
            "region": "us-sanjose-1",
            "sshUser": "user",
            "services": ["SSH", "RTI base layout"],
        },
    ]


def _seed_core_lifecycle_job(client, engagement_id: str, events: list[JobEvent]):
    finished_at = datetime.now(timezone.utc) - timedelta(days=1)
    started_at = finished_at - timedelta(minutes=4)
    created_at = finished_at - timedelta(minutes=5)
    with client.application.storage_context():
        SqlAlchemyJobRepository().save(
            StoredJobRun(
                id=f"job-{engagement_id}-core-lifecycle",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={
                    "engagementId": engagement_id,
                    "engagementName": "ZY01",
                    "target": {"name": "barragan-testing", "region": "us-sanjose-1"},
                },
                artifact_refs=[],
                created_at=created_at.isoformat(),
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                events=events,
            )
        )


def _sketch_chain_model(engagement_id: str, chain_id: str, proxy: str, provider: str, status: str) -> SketchChainModel:
    return SketchChainModel(
        engagement_id=engagement_id,
        chain_id=chain_id,
        assigned_proxy=proxy,
        middle_provider=provider,
        middle_region="us-sea" if provider == "linode" else "sfo3",
        middle_size="g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
        edge_provider=provider,
        edge_region="us-sea" if provider == "linode" else "sfo3",
        edge_size="g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb",
        status=status,
        nodes=[],
    )


def _seed_bootstrapped_outbound_chain(
    client, engagement_id: str, deploy_job_id: str, *, chain_id="chain-1", proxy="proxy01",
    middle_ip="203.0.113.20", edge_ip="203.0.113.30",
):
    with client.application.storage_context():
        db.session.add(_sketch_chain_model(engagement_id, chain_id, proxy, "linode", "deployed"))
        chain = SketchChainModel.query.filter_by(engagement_id=engagement_id, chain_id=chain_id).one()
        chain.deploy_job_id = deploy_job_id
        chain.nodes = [
            {"chainId": chain_id, "hostname": f"{role}-zy01-{chain_id}", "provider": "linode",
             "role": role, "publicIp": address, "region": "us-sea", "proxy": proxy, "status": "deployed"}
            for role, address in (("middle", middle_ip), ("edge", edge_ip))
        ]
        repository = SqlAlchemyJobRepository()
        job = repository.get(deploy_job_id)
        assert job is not None
        repository.save(replace(job, events=[*job.events, JobEvent(len(job.events) + 1, "info", "sketch bootstrap succeeded", {"bootstrap": "succeeded"})]))
        db.session.commit()


def _seed_outbound_apply_prerequisites(client, engagement_id: str, outbound_channels=None):
    from app.services.sketch_transport_ssh_keys import ensure_sketch_transport_ssh_key
    with client.application.storage_context():
        ensure_sketch_transport_ssh_key(engagement_id)
    outbound_channels = outbound_channels or [_pending_outbound_channel("ZY01", "chain-1")]
    with client.application.storage_context():
        repository = SqlAlchemyJobRepository()
        repository.save(
            StoredJobRun(
                id=f"job-{engagement_id}-core",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target="oci-compartment:barragan-testing",
                target_type="oci_compartment",
                target_id="ocid1.compartment.oc1..testing",
                requested_by="operator",
                input={
                    "engagementId": engagement_id,
                    "chainId": "chain-1",
                    "sshPrivateKeyPath": "/tmp/barragan-keys/zy01-sketch",
                },
                artifact_refs=[],
                created_at="2026-06-04T12:00:00+00:00",
                started_at="2026-06-04T12:01:00+00:00",
                finished_at="2026-06-04T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "operator inspection ready",
                        {
                            "workspaceDir": str(client.application.state.config.DATA_DIR / "core-workspace"),
                            "connectionDetails": [
                                {
                                    "role": "homebase",
                                    "displayName": "homebase-zy01",
                                    "sshAlias": "homebase-zy01",
                                    "publicIp": "203.0.113.10",
                                    "privateIp": "192.168.0.10",
                                    "sshUser": "user",
                                },
                                {
                                    "role": "proxy01",
                                    "displayName": "proxy01-zy01",
                                    "sshAlias": "proxy01-zy01",
                                    "publicIp": "203.0.113.11",
                                    "privateIp": "192.168.2.11",
                                    "sshUser": "user",
                                },
                                {
                                    "role": "proxy02",
                                    "displayName": "proxy02-zy01",
                                    "sshAlias": "proxy02-zy01",
                                    "publicIp": "203.0.113.12",
                                    "privateIp": "192.168.2.12",
                                    "sshUser": "user",
                                },
                            ]
                        },
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id=f"job-{engagement_id}-outbound",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:11:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "pending outbound channel artifacts derived",
                        {"outboundChannels": outbound_channels},
                    )
                ],
            )
        )

    _seed_bootstrapped_outbound_chain(client, engagement_id, f"job-{engagement_id}-outbound")

def _seed_inbound_channel(client, engagement_id: str):
    from app.services.sketch_ssh_keys import ensure_sketch_ssh_key
    with client.application.storage_context():
        ensure_sketch_ssh_key(engagement_id)
    repository = SqlAlchemyJobRepository()
    with client.application.storage_context():
        repository.save(
            StoredJobRun(
                id=f"job-{engagement_id}-inbound-core",
                action="pilot_standard_rti_guarded_execute",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={"engagementId": engagement_id},
                artifact_refs=[],
                created_at="2026-06-04T12:00:00+00:00",
                started_at="2026-06-04T12:00:00+00:00",
                finished_at="2026-06-04T12:05:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "connection details recorded",
                        {
                            "connectionDetails": [
                                {
                                    "role": "homebase",
                                    "displayName": "homebase-zy01",
                                    "sshAlias": "homebase-zy01",
                                    "publicIp": "203.0.113.10",
                                    "privateIp": "192.168.0.10",
                                    "sshUser": "user",
                                },
                                {
                                    "role": "proxy01",
                                    "displayName": "proxy01-zy01",
                                    "sshAlias": "proxy01-zy01",
                                    "publicIp": "203.0.113.11",
                                    "privateIp": "192.168.2.11",
                                    "sshUser": "user",
                                },
                            ]
                        },
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id=f"job-{engagement_id}-inbound-sketch",
                action="linode_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={
                    "engagementId": engagement_id,
                    "chainId": "chain-1",
                    "sshPrivateKeyPath": "/tmp/barragan-keys/zy01-sketch",
                },
                artifact_refs=[],
                created_at="2026-06-04T12:10:00+00:00",
                started_at="2026-06-04T12:10:00+00:00",
                finished_at="2026-06-04T12:15:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "sketch infrastructure recorded",
                        {
                            "sketchInfrastructure": [
                                {
                                    "chainId": "chain-1",
                                    "hostname": "middle01-zy01",
                                    "provider": "linode",
                                    "role": "middle",
                                    "publicIp": "198.51.100.20",
                                    "region": "us-sea",
                                    "proxy": "proxy01",
                                    "status": "deployed",
                                },
                                {
                                    "chainId": "chain-1",
                                    "hostname": "edge-zy01-us-sea-01",
                                    "provider": "linode",
                                    "role": "edge",
                                    "publicIp": "198.51.100.30",
                                    "region": "us-sea",
                                    "proxy": "proxy01",
                                    "status": "deployed",
                                },
                            ]
                        },
                    )
                ],
            )
        )
        repository.save(
            StoredJobRun(
                id=f"job-{engagement_id}-inbound-sketch-other-provider",
                action="digitalocean_sketch_deploy",
                status="succeeded",
                target=f"engagement:{engagement_id}",
                target_type="engagement",
                target_id=engagement_id,
                requested_by="operator",
                input={
                    "engagementId": engagement_id,
                    "chainId": "chain-2",
                    "sshPrivateKeyPath": "/tmp/barragan-keys/wrong-provider-sketch",
                },
                artifact_refs=[],
                created_at="2026-06-04T12:20:00+00:00",
                started_at="2026-06-04T12:20:00+00:00",
                finished_at="2026-06-04T12:25:00+00:00",
                events=[
                    JobEvent(
                        1,
                        "info",
                        "other provider key path recorded",
                        {
                            "chainId": "chain-2",
                            "provider": "digitalocean",
                        },
                    )
                ],
            )
        )
    client.patch(
        f"/api/engagements/{engagement_id}/operations",
        json={
            "inboundChannels": [
                {
                    "channelId": "c2-primary",
                    "domain": "c2.example.invalid",
                    "protocol": "HTTPS",
                    "mode": "tcp-forward",
                    "externalPort": "443",
                    "edge": "edge-zy01-us-sea-01",
                    "middle": "middle01-zy01",
                    "proxy": "proxy01-zy01",
                    "terminatesOn": "homebase-zy01",
                    "service": "Mythic",
                    "internalPort": "7443",
                    "purpose": "C2 ingress",
                    "status": "Not Ready",
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nmust-not-persist\n-----END OPENSSH PRIVATE KEY-----",
                }
            ],
        },
    )


def _make_executable(tmp_path, name):
    path = tmp_path / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def _inject_dashboard_discovery_evidence(monkeypatch):
    from app.services import provider_reconciliation
    monkeypatch.setattr(provider_reconciliation, "discover_provider_inventory", lambda: {
        "resources": provider_reconciliation.discover_provider_resources(),
        "evidence": {"status": "checked", "observedAt": "2026-10-22T00:00:00+00:00",
                     "cached": False, "ageSeconds": 0, "detail": "Injected provider inventory.", "providers": []},
    })
