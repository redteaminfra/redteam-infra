# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant Inspector hook recorder journals stages without invoking providers."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.services.observer_checks import InspectorCreateStage
from app.services import provider_keyed_inspector_stage as service
from app.services.provider_keyed_inspector_create_intent import reserve_keyed_inspector_create_intent
from test_provider_keyed_inspector_create_intent import _case, _record


def setup(tmp_path):
    jobs, parent, scope, plans, child, settings, resources, credentials, key, options = _case(tmp_path)
    receipt = reserve_keyed_inspector_create_intent(parent.id, **options)
    recorder = service.make_keyed_inspector_stage_recorder(
        receipt, environment="devtest", job_repository=jobs, plan_repository=plans,
        settings_repository=settings, provider_resource_repository=resources,
        credential_repository=credentials, lease_lookup=options["lease_lookup"],
        key_fingerprint_reader=lambda: key[0], now=lambda: datetime.now(timezone.utc),
    )
    return recorder, jobs, parent, scope, plans, settings, resources, credentials, key, receipt


@pytest.mark.parametrize("drift", ["claim", "secret"])
def test_old_receipt_cannot_bind_rotated_claim_or_replaced_secret(drift, tmp_path):
    jobs, parent, _scope, plans, _child, settings, resources, credentials, key, options = _case(tmp_path)
    receipt = reserve_keyed_inspector_create_intent(parent.id, **options)
    if drift == "claim":
        current = jobs.get(receipt.coordinator_job_id)
        jobs.save(replace(current, input={**current.input, "claimToken": "b" * 32}))
    else:
        credentials.rows[0] = replace(credentials.rows[0], encrypted_secret="different-ciphertext")
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        service.make_keyed_inspector_stage_recorder(
            receipt, environment="devtest", job_repository=jobs, plan_repository=plans,
            settings_repository=settings, provider_resource_repository=resources,
            credential_repository=credentials, lease_lookup=options["lease_lookup"],
            key_fingerprint_reader=lambda: key[0],
        )


def test_records_exact_linode_stage_sequence(tmp_path):
    # Keyed-v2 Inspector creation rejects DigitalOcean before any stage exists.
    provider = "linode"
    record, jobs, _parent, _scope, _plans, _settings, _resources, _credentials, _key, receipt = setup(tmp_path)
    name = receipt.resource_name
    stages = [
        InspectorCreateStage(provider, name, "firewall", "before_post"),
        InspectorCreateStage(provider, name, "firewall", "response_received", resource_id="42"),
        InspectorCreateStage(provider, name, "instance", "before_post", firewall_id="42"),
        InspectorCreateStage(provider, name, "instance", "response_received", resource_id="123", firewall_id="42"),
    ]
    for stage in stages:
        record(stage)
    current = jobs.get(receipt.coordinator_job_id)
    assert len(current.events) == 5 + len(stages)
    assert current.events[-1].data["resourceName"] == name
    assert "ENCRYPTED-SECRET" not in repr(current.events)
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(stages[-1])


@pytest.mark.parametrize("drift", ["parent", "lease", "settings", "credential", "key", "record", "expiry"])
def test_preappend_drift_vetoes_and_poison_callback(drift, tmp_path):
    record, jobs, parent, scope, plans, settings, resources, credentials, key, receipt = setup(tmp_path)
    before = jobs.get(receipt.coordinator_job_id)
    if drift == "parent":
        jobs.save(replace(parent, input={**parent.input, "phase": "attention"}))
    elif drift == "lease":
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")
    elif drift == "settings":
        settings.row = replace(settings.row, size="other")
    elif drift == "credential":
        credentials.rows[0] = replace(credentials.rows[0], updated_at="2026-10-08T00:01:00+00:00")
    elif drift == "key":
        key[0] = "f" * 64
    elif drift == "record":
        resources.rows.append(_record(parent.target_id))
    else:
        jobs.save(replace(before, input={**before.input,
                                         "claimExpiresAt": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()}))
    event = InspectorCreateStage("linode", receipt.resource_name, "firewall", "before_post")
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(event)
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(event)
    assert len(jobs.get(receipt.coordinator_job_id).events) == 5


def test_invalid_stage_does_not_append_or_retry(tmp_path):
    record, jobs, _parent, _scope, _plans, _settings, _resources, _credentials, _key, receipt = setup(tmp_path)
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(InspectorCreateStage("linode", receipt.resource_name, "instance", "before_post"))
    assert len(jobs.get(receipt.coordinator_job_id).events) == 5
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(InspectorCreateStage("linode", receipt.resource_name, "firewall", "before_post"))


def test_postappend_drift_is_attention_without_replay(tmp_path):
    record, jobs, parent, _scope, _plans, settings, _resources, _credentials, _key, receipt = setup(tmp_path)
    original = jobs.append_keyed_inspector_stage_if_running_claimed
    def append_and_drift(*args, **kwargs):
        written = original(*args, **kwargs)
        settings.row = replace(settings.row, size="other")
        return written
    jobs.append_keyed_inspector_stage_if_running_claimed = append_and_drift
    event = InspectorCreateStage("linode", receipt.resource_name, "firewall", "before_post")
    with pytest.raises(service.ProviderKeyedInspectorStageAttention, match="recorded"):
        record(event)
    assert len(jobs.get(receipt.coordinator_job_id).events) == 6
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(event)


def test_stale_journal_or_competing_writer_vetoes(tmp_path):
    record, jobs, _parent, _scope, _plans, _settings, _resources, _credentials, _key, receipt = setup(tmp_path)
    other = service.make_keyed_inspector_stage_recorder(
        receipt, environment="devtest", job_repository=jobs,
        plan_repository=_plans, settings_repository=_settings,
        provider_resource_repository=_resources, credential_repository=_credentials,
        lease_lookup=lambda _engagement: _plans.lease,
        key_fingerprint_reader=lambda: _key[0], now=lambda: datetime.now(timezone.utc),
    )
    event = InspectorCreateStage("linode", receipt.resource_name, "firewall", "before_post")
    record(event)
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        other(event)
    assert len(jobs.get(receipt.coordinator_job_id).events) == 6


def test_rotated_claim_cannot_authorize_stale_recorder(tmp_path):
    record, jobs, _parent, _scope, _plans, _settings, _resources, _credentials, _key, receipt = setup(tmp_path)
    current = jobs.get(receipt.coordinator_job_id)
    rotated = replace(current, input={**current.input, "claimToken": "b" * 32,
                                      "claimClaimedAt": datetime.now(timezone.utc).isoformat()})
    jobs.save(rotated)
    event = InspectorCreateStage("linode", receipt.resource_name, "firewall", "before_post")
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(event)
    assert jobs.get(receipt.coordinator_job_id) == rotated
    with pytest.raises(service.ProviderKeyedInspectorStageAttention):
        record(event)
