# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network SQLAlchemy transaction tests for proved Inspector ownership."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from copy import deepcopy

import pytest

from app.domain.deployment_plan import DeploymentPlan
from app.services.observer_checks import (
    INSPECTION_ACTION, ObserverHost, _inspector_firewall_label,
)
from app.services.provider_keyed_inspector_materialize import (
    InspectorMaterializationAttention, materialize_proved_keyed_inspector,
    recover_materialized_keyed_inspector,
)
from app.services.provider_keyed_inspector_provider_proof import InspectorProviderProof
from app.services.provider_keyed_inspector_settlement import settle_submitted_keyed_inspector
from app.services.provider_keyed_inspector_submit import submit_keyed_inspector_once
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.database import db
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_submit import FakeProvider, setup
from test_provider_keyed_inspector_provider_proof import linode_responses


def _case(tmp_path, provider="linode"):
    source_jobs, parent, _plans, settings, credentials, key, receipt, submit_options = setup(tmp_path, provider)
    submitted = submit_keyed_inspector_once(
        receipt, provider_factory=lambda kind, source: FakeProvider(kind, source), **submit_options,
    )
    region = "us-east" if provider == "linode" else "nyc3"
    size = "g6-nanode-1" if provider == "linode" else "s-1vcpu-1gb"
    firewall = {
        "provider": provider, "resourceType": "firewall", "resourceId": submitted.firewall_id,
        "name": _inspector_firewall_label(provider, submitted.resource_name),
        "managementSourceCidr": "8.8.8.8/32",
    }
    if provider == "digitalocean":
        firewall["tag"] = submitted.tag_name
    proof = InspectorProviderProof(
        host=ObserverHost(
            provider, "instance" if provider == "linode" else "droplet",
            submitted.host_id, submitted.resource_name, region, "1.1.1.1",
            ssh_user="barragan", status="running" if provider == "linode" else "active",
            metadata={"providerFirewall": firewall, "publicIps": ["1.1.1.1"]},
        ),
        firewall_id=submitted.firewall_id, management_cidr="8.8.8.8/32",
        tag_name=submitted.tag_name,
    )
    state = db.configure("sqlite:///:memory:")
    return state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof


def _persist(state, source_jobs, parent, settings, credentials):
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        instant = datetime.now(timezone.utc).isoformat()
        for row in source_jobs.list():
            jobs.save(replace(
                row, created_at=row.created_at or instant,
                started_at=row.started_at or (instant if row.status != "queued" else None),
                finished_at=row.finished_at or (
                    instant if row.status in {"succeeded", "failed"} else None),
            ))
        plan_id = jobs.get(parent.id).input["scopeSnapshot"]["providerScopes"][0]["corePlanId"]
        plans = SqlAlchemyDeploymentPlanRepository()
        plans.save(DeploymentPlan(
            id=plan_id, engagement_id=parent.target_id, revision_id="revision-1",
            status="applied", stage="applied", apply_job_id="job-core",
        ))
        plans.acquire(parent.target_id, plan_id, "provider_keyed_teardown_fence")
        SqlAlchemyObserverSettingsRepository().save(settings.row)
        from app.storage.models import CredentialModel
        credential = credentials.rows[0]
        db.session.add(CredentialModel(
            id=credential.id, provider=credential.provider, alias=credential.alias,
            status=credential.status, description=credential.description,
            encrypted_secret=credential.encrypted_secret, is_default=credential.is_default,
            created_at=datetime.fromisoformat(credential.created_at),
            updated_at=datetime.fromisoformat(credential.updated_at),
        ))
        db.session.commit()


def _run(state, receipt, submitted, proof, key):
    with db.bind(state):
        return materialize_proved_keyed_inspector(
            receipt, submitted, environment="devtest", settler=lambda *_a, **_kw: proof,
            key_fingerprint_reader=lambda: key[0],
        )


def test_atomic_owned_pair_link_and_read_only_recovery(tmp_path):
    provider = "linode"  # Keyed-v2 Inspector creation currently requires Linode.
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof = _case(tmp_path, provider)
    _persist(state, source_jobs, parent, settings, credentials)
    result = _run(state, receipt, submitted, proof, key)
    assert result.status == "preparation_required" and result.cleanup_required is True
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        resources = SqlAlchemyProviderResourceRepository()
        child = jobs.get(receipt.coordinator_job_id)
        assert child.input["phase"] == "inspector_owned_unprepared"
        assert child.events[-1].message == "inspector_owned_unprepared"
        assert len(resources.list_for_engagement(parent.target_id)) == 2
        host = resources.get(result.host_record_id)
        firewall = resources.get(result.firewall_record_id)
        assert host.status == firewall.status == "preparation_required"
        assert host.metadata["cleanupRequired"] is True
        assert "tag" not in host.metadata["providerFirewall"]
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).current_host == {}
        original_events = child.events
    assert _run(state, receipt, submitted, proof, key) == result
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id).events == original_events
        assert recover_materialized_keyed_inspector(
            receipt.coordinator_job_id, parent.target_id, environment="devtest") == result


def test_second_insert_failure_rolls_back_phase_first_row_and_event(tmp_path, monkeypatch):
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof = _case(tmp_path)
    _persist(state, source_jobs, parent, settings, credentials)
    from app.storage.models import ProviderResourceRecordModel

    def fail_after_first(self, host, firewall):
        db.session.add(ProviderResourceRecordModel(
            id=host.id, engagement_id=host.engagement_id, engagement_name=host.engagement_name,
            provider=host.provider, resource_type=host.resource_type, resource_id=host.resource_id,
            name=host.name, region=host.region, lifecycle_state=host.lifecycle_state,
            status=host.status, source=host.source, metadata_json=host.metadata,
            adoption_job_id=host.adoption_job_id, adopted_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        ))
        db.session.flush()
        raise RuntimeError("second insert failed")

    monkeypatch.setattr(SqlAlchemyProviderResourceRepository, "add_new_owned_pair_uncommitted", fail_after_first)
    with pytest.raises(InspectorMaterializationAttention):
        _run(state, receipt, submitted, proof, key)
    with db.bind(state):
        assert SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id) == []
        child = SqlAlchemyJobRepository().get(receipt.coordinator_job_id)
        assert child.input["phase"] == "inspector_create_started"
        assert child.events[-1].message == "inspector_create_stage"


def test_offline_linode_settles_to_running_before_atomic_materialization(tmp_path):
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, _proof = _case(tmp_path)
    _persist(state, source_jobs, parent, settings, credentials)
    responses = linode_responses()

    class SettlingGet:
        def __init__(self):
            self.instance_reads = 0
            self.methods = []

        def request(self, method, path, token, body=None):
            assert method == "GET" and body is None and token == "private-token"
            self.methods.append(method)
            result = deepcopy(responses[path])
            if path == "/linode/instances/123":
                self.instance_reads += 1
                if self.instance_reads == 1:
                    result["status"] = "offline"
            return result

    transport = SettlingGet()
    ticks = [0.0]

    def settle(original_receipt, original_submission, **options):
        return settle_submitted_keyed_inspector(
            original_receipt, original_submission, **options,
            transport_factory=lambda _provider: transport,
            decrypt_secret=lambda _ciphertext: "private-token",
            monotonic=lambda: ticks[0], sleep=lambda duration: ticks.__setitem__(0, ticks[0] + duration),
        )

    with db.bind(state):
        result = materialize_proved_keyed_inspector(
            receipt, submitted, environment="devtest", settler=settle,
            key_fingerprint_reader=lambda: key[0],
        )
        assert result.status == "preparation_required"
        assert SqlAlchemyProviderResourceRepository().get(result.host_record_id).status == "preparation_required"
        assert recover_materialized_keyed_inspector(
            receipt.coordinator_job_id, parent.target_id, environment="devtest") == result
    assert transport.instance_reads == 2 and ticks[0] == 10.0
    assert set(transport.methods) == {"GET"}


def test_read_only_recovery_rejects_extra_active_inspector_record(tmp_path):
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof = _case(tmp_path)
    _persist(state, source_jobs, parent, settings, credentials)
    result = _run(state, receipt, submitted, proof, key)
    with db.bind(state):
        resources = SqlAlchemyProviderResourceRepository()
        original = resources.get(result.host_record_id)
        resources.save(replace(original, id="linode:inspector:another", resource_id="another"))
        with pytest.raises(InspectorMaterializationAttention):
            recover_materialized_keyed_inspector(
                receipt.coordinator_job_id, parent.target_id, environment="devtest")


@pytest.mark.parametrize("tamper", [
    "host_type", "firewall_type", "firewall_label", "host_metadata", "firewall_metadata",
])
def test_read_only_recovery_rejects_record_shape_tamper(tmp_path, tamper):
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof = _case(tmp_path)
    _persist(state, source_jobs, parent, settings, credentials)
    result = _run(state, receipt, submitted, proof, key)
    with db.bind(state):
        resources = SqlAlchemyProviderResourceRepository()
        host = resources.get(result.host_record_id)
        firewall = resources.get(result.firewall_record_id)
        if tamper == "host_type":
            resources.save(replace(host, resource_type="inspector_droplet"))
        elif tamper == "firewall_type":
            resources.save(replace(firewall, resource_type="inspector_instance"))
        elif tamper == "firewall_label":
            resources.save(replace(firewall, name="manual-firewall"))
        elif tamper == "host_metadata":
            resources.save(replace(host, metadata={**host.metadata, "prepared": True}))
        else:
            resources.save(replace(firewall, metadata={**firewall.metadata, "prepared": True}))
        with pytest.raises(InspectorMaterializationAttention):
            recover_materialized_keyed_inspector(
                receipt.coordinator_job_id, parent.target_id, environment="devtest")


@pytest.mark.parametrize("drift", [
    "expired", "rotated", "collision", "credential", "scope", "journal", "lifecycle",
])
def test_authority_drift_blocks_materialization(tmp_path, drift):
    state, source_jobs, parent, settings, credentials, key, receipt, submitted, proof = _case(tmp_path)
    _persist(state, source_jobs, parent, settings, credentials)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        child = jobs.get(receipt.coordinator_job_id)
        if drift == "expired":
            jobs.save(replace(child, input={**child.input,
                "claimExpiresAt": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}))
        elif drift == "rotated":
            jobs.save(replace(child, input={**child.input, "claimToken": "b" * 32}))
        elif drift == "collision":
            from app.storage.provider_resource_repository import StoredProviderResourceRecord
            SqlAlchemyProviderResourceRepository().save(StoredProviderResourceRecord(
                id=f"linode:inspector:{submitted.host_id}", engagement_id=parent.target_id,
                engagement_name="opaque", provider="linode", resource_type="inspector_instance",
                resource_id=submitted.host_id, name="manual", region="us-east",
                lifecycle_state="active", status="active", source="manual",
                metadata={}, adoption_job_id="", adopted_at="2026-10-08T00:00:00+00:00",
                updated_at="2026-10-08T00:00:00+00:00"))
        elif drift == "credential":
            repo = SqlAlchemyCredentialRepository()
            old = repo.get(credentials.rows[0].id)
            repo.save(replace(old, encrypted_secret="changed"))
        elif drift == "journal":
            stage = child.events[-1]
            jobs.save(replace(child, events=[*child.events[:-1], replace(
                stage, data={**stage.data, "resourceId": "999"})]))
        elif drift == "lifecycle":
            jobs.save(replace(child, id="job-concurrent-inspector", action=INSPECTION_ACTION,
                              status="queued", started_at=None, events=child.events[:1]))
        else:
            plans = SqlAlchemyDeploymentPlanRepository()
            plans.retag(parent.target_id, child.input["corePlanId"], "different-operation")
    with pytest.raises(InspectorMaterializationAttention):
        _run(state, receipt, submitted, proof, key)
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(receipt.coordinator_job_id).input["phase"] == "inspector_create_started"
