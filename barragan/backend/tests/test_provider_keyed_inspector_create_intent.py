# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant one-shot Inspector intent: no provider, SSH, settings or resource write."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib

import pytest

from app.services import provider_keyed_comprehensive_teardown as coordinator
from app.services import provider_keyed_inspector_create_intent as service
from app.services import engagement_teardown
from app.services.observer_checks import (
    INSPECTION_ACTION, INSPECTOR_READINESS_ACTION, INSPECTOR_CLEANUP_ACTION,
)
from app.storage.credential_repository import StoredCredential
from app.storage.observer_settings_repository import StoredObserverSettings
from app.storage.provider_resource_repository import StoredProviderResourceRecord
from test_provider_keyed_comprehensive_teardown import _options


class Settings:
    def __init__(self, row):
        self.row = row
        self.reads = 0
        self.after_read = None

    def get(self, engagement_id):
        self.reads += 1
        if self.after_read:
            self.after_read(self)
        return self.row if self.row.engagement_id == engagement_id else None

    def save(self, _row):
        pytest.fail("intent must not write settings")


class Resources:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.reads = 0
        self.after_read = None

    def list_for_engagement(self, engagement_id):
        self.reads += 1
        if self.after_read:
            self.after_read(self)
        return [row for row in self.rows if row.engagement_id == engagement_id]

    def save(self, _row):
        pytest.fail("intent must not write provider resources")


class Credentials:
    def __init__(self, row):
        self.rows = [row]
        self.reads = 0
        self.after_read = None

    def list(self, provider=None):
        self.reads += 1
        if self.after_read:
            self.after_read(self)
        return [row for row in self.rows if provider is None or row.provider == provider]

    def get_default(self, provider):
        selected = [row for row in self.rows if row.provider == provider and row.is_default and row.status == "active"]
        return selected[0] if selected else None

    def save(self, _row):
        pytest.fail("intent must not write credentials")


def _case(tmp_path):
    jobs, queued, scope, plans, _clock, handoff = _options(tmp_path)
    child = coordinator.run_provider_keyed_comprehensive_handoff(queued.id, **handoff)
    assert child.input["phase"] == "awaiting_inspector_preflight"
    stamp = "2026-10-08T00:00:00+00:00"
    settings = Settings(StoredObserverSettings(
        engagement_id=queued.target_id, enabled=True, provider="linode",
        region="us-east", size="g6-nanode-1", mode="continuous",
        schedule_weekdays=[], schedule_time_utc="00:00", check_families=[],
        forbidden_tcp_ports=[], port_scan_profiles=[], current_host={},
        idle_retention_until="", last_scheduled_slot="", last_mutation_job_inspected="",
        created_at=stamp, updated_at=stamp,
    ))
    resources = Resources()
    credentials = Credentials(StoredCredential(
        id="cred-1", provider="linode", alias="inspector-linode", status="active",
        description="", encrypted_secret="ENCRYPTED-SECRET-MUST-STAY-PRIVATE",
        is_default=True, created_at=stamp, updated_at=stamp,
    ))
    key = ["e" * 64]
    options = dict(
        environment="devtest", job_repository=jobs, plan_repository=plans,
        settings_repository=settings, provider_resource_repository=resources,
        credential_repository=credentials, lease_lookup=handoff["lease_lookup"],
        key_fingerprint_reader=lambda: key[0], now=lambda: datetime.now(timezone.utc),
        management_source_resolver=lambda: "8.8.8.8/32",
        token_factory=lambda: "f" * 32, name_token_factory=lambda: "a" * 32,
    )
    return jobs, queued, scope, plans, child, settings, resources, credentials, key, options


def _record(engagement_id):
    return StoredProviderResourceRecord(
        id="linode:inspector:123", engagement_id=engagement_id,
        engagement_name="opaque", provider="linode", resource_type="inspector_instance",
        resource_id="123", name="opaque", region="us-east", lifecycle_state="active",
        status="active", source="barragan_inspector_job",
        metadata={"barraganOwned": True, "role": "inspector"},
        adoption_job_id="prior-job", adopted_at="2026-10-08T00:00:00+00:00",
        updated_at="2026-10-08T00:00:00+00:00",
    )


def _active_inspector_job(child, action, status):
    return replace(
        child, id=f"job-{action}-{status}", action=action, status=status,
        input={}, started_at=None if status == "queued" else child.started_at,
        events=child.events[:1],
    )


def test_intent_is_one_shot_nonsecret_and_dormant(tmp_path):
    jobs, queued, scope, plans, child, settings, resources, credentials, key, options = _case(tmp_path)
    original_parent = jobs.get(queued.id)
    receipt = service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert receipt.coordinator_job_id == child.id
    assert receipt.resource_name == "inspector-" + "a" * 32
    assert receipt.provider_create_authorized is False
    current = jobs.get(child.id)
    assert current.input["phase"] == "inspector_create_started"
    assert current.events[-1].message == "inspector_create_started"
    assert current.events[-1].data["credentialAlias"] == "inspector-linode"
    assert current.events[-1].data["credentialId"] == credentials.rows[0].id
    assert current.events[-1].data["credentialSha256"] == receipt.encrypted_secret_sha256
    assert current.events[-1].data["credentialUpdatedAt"] == credentials.rows[0].updated_at
    assert current.events[-1].data["keyFingerprintSha256"] == key[0]
    assert current.events[-1].data["managementSourceCidr"] == "8.8.8.8/32"
    assert current.events[-1].data["claimGenerationSha256"] == service.inspector_claim_generation_digest(
        token=receipt.claim_token, claimed_at=receipt.claim_claimed_at)
    assert receipt.claim_token not in repr(receipt)
    assert "ENCRYPTED-SECRET" not in str(current.events)
    assert jobs.get(queued.id) == original_parent and settings.row.current_host == {}
    assert resources.rows == [] and plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")
    with pytest.raises(service.ProviderKeyedInspectorCreateAttention):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id) == current


def test_digitalocean_inspector_rejected_before_one_shot_claim(tmp_path):
    jobs, queued, _scope, _plans, child, settings, _resources, credentials, _key, options = _case(tmp_path)
    settings.row = replace(settings.row, provider="digitalocean", region="nyc3", size="s-1vcpu-1gb")
    credentials.rows[0] = replace(credentials.rows[0], provider="digitalocean", alias="inspector-do")
    original = jobs.get(child.id)
    claims = []
    claim = jobs.claim_lease
    def count_claim(*args, **kwargs):
        claims.append(args)
        return claim(*args, **kwargs)
    jobs.claim_lease = count_claim
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError, match="select Linode"):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert claims == []
    assert jobs.get(child.id) == original


def test_recorded_intent_rejects_valid_token_rotation(tmp_path):
    jobs, queued, _scope, plans, _child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    receipt = service.reserve_keyed_inspector_create_intent(queued.id, **options)
    from app.services.provider_keyed_comprehensive_teardown import _boundary
    parent, core, snapshot, _operation = _boundary(queued.id, jobs, plans, options["lease_lookup"])
    current = jobs.get(receipt.coordinator_job_id)
    assert service.recorded_keyed_inspector_intent(current, parent, core, snapshot)
    rotated = replace(current, input={**current.input, "claimToken": "b" * 32})
    assert not service.recorded_keyed_inspector_intent(rotated, parent, core, snapshot)
    missing_credential_digest = replace(current, events=[*current.events[:-1], replace(
        current.events[-1], data={key: value for key, value in current.events[-1].data.items()
                                  if key != "credentialSha256"})])
    assert not service.recorded_keyed_inspector_intent(
        missing_credential_digest, parent, core, snapshot)
    missing_claim_time = replace(current, input={
        key: value for key, value in current.input.items() if key != "claimClaimedAt"
    })
    assert not service.recorded_keyed_inspector_intent(missing_claim_time, parent, core, snapshot)


@pytest.mark.parametrize("source", [
    "8.8.8.0/24", "10.0.0.1/32", "224.0.0.1/32", "127.0.0.1/32",
    "169.254.0.1/32", "0.0.0.0/32", "8.8.8.8/31", "8.8.8.8",
])
def test_unverified_management_source_stops_before_claim(source, tmp_path):
    jobs, queued, _scope, _plans, child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    original = jobs.get(child.id)
    options["management_source_resolver"] = lambda: source
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id) == original


def test_management_source_resolver_failure_stops_before_claim(tmp_path):
    jobs, queued, _scope, _plans, child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    original = jobs.get(child.id)
    def fail():
        raise RuntimeError("resolver private diagnostics")
    options["management_source_resolver"] = fail
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError) as error:
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert "private diagnostics" not in str(error.value)
    assert jobs.get(child.id) == original


def test_coordinator_recovery_reports_attention_without_rearming(tmp_path):
    jobs, queued, _scope, _plans, child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    service.reserve_keyed_inspector_create_intent(queued.id, **options)
    coordinator_options = dict(
        environment="devtest", job_repository=jobs,
        plan_repository=options["plan_repository"], lease_lookup=options["lease_lookup"],
    )
    with pytest.raises(coordinator.ProviderKeyedComprehensiveTeardownAttention):
        coordinator.run_provider_keyed_comprehensive_handoff(queued.id, **coordinator_options)
    before = jobs.get(child.id)
    assert engagement_teardown.recover_engagement_teardowns(
        job_repository=jobs,
        provider_keyed_coordinator=lambda parent_id: coordinator.run_provider_keyed_comprehensive_handoff(
            parent_id, **coordinator_options),
        provider_keyed_environment="devtest",
    ) == []
    assert jobs.get(child.id) == before


@pytest.mark.parametrize("drift", ["parent", "lease", "settings", "credential", "key", "record", "duplicate-default"])
def test_before_claim_authority_drift_vetoes_intent(tmp_path, drift):
    jobs, queued, scope, plans, child, settings, resources, credentials, key, options = _case(tmp_path)
    if drift == "parent":
        jobs.save(replace(queued, input={**queued.input, "phase": "attention"}))
    elif drift == "lease":
        plans.lease = (scope["corePlanId"], "provider_keyed_initial")
    elif drift == "settings":
        settings.row = replace(settings.row, current_host={"resourceId": "untracked"})
    elif drift == "credential":
        credentials.rows[0] = replace(credentials.rows[0], status="disabled")
    elif drift == "key":
        key[0] = "invalid"
    elif drift == "record":
        resources.rows.append(_record(queued.target_id))
    else:
        credentials.rows.append(replace(credentials.rows[0], id="cred-2"))
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id).input["phase"] == "awaiting_inspector_preflight"
    assert len(jobs.get(child.id).events) == 4


def test_claim_race_and_stale_token_cannot_record_intent(tmp_path):
    jobs, queued, _scope, _plans, child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    original = jobs.claim_lease
    def lose_claim(*args, **kwargs):
        return None
    jobs.claim_lease = lose_claim
    try:
        with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
            service.reserve_keyed_inspector_create_intent(queued.id, **options)
    finally:
        jobs.claim_lease = original
    assert jobs.get(child.id) == child


@pytest.mark.parametrize("action", [
    INSPECTION_ACTION, INSPECTOR_READINESS_ACTION, INSPECTOR_CLEANUP_ACTION,
])
@pytest.mark.parametrize("status", ["queued", "running"])
def test_active_inspector_lifecycle_job_vetoes_create_before_resource_record(tmp_path, action, status):
    jobs, queued, _scope, _plans, child, _settings, resources, _credentials, _key, options = _case(tmp_path)
    jobs.save(_active_inspector_job(child, action, status))
    assert resources.rows == []
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    retained = jobs.get(child.id)
    assert retained.input["phase"] == "awaiting_inspector_preflight"
    assert len(retained.events) == 4


@pytest.mark.parametrize("drift", ["parent", "lease", "settings", "credential", "key", "record", "lifecycle"])
def test_postclaim_authority_drift_cannot_append_intent(tmp_path, drift):
    jobs, queued, scope, plans, child, settings, resources, credentials, key, options = _case(tmp_path)
    original = jobs.claim_lease
    def claim_and_drift(*args, **kwargs):
        claimed = original(*args, **kwargs)
        if drift == "parent":
            jobs.save(replace(queued, input={**queued.input, "phase": "attention"}))
        elif drift == "lease":
            plans.lease = (scope["corePlanId"], "provider_keyed_initial")
        elif drift == "settings":
            settings.row = replace(settings.row, region="us-west")
        elif drift == "credential":
            credentials.rows[0] = replace(credentials.rows[0], updated_at="2026-10-08T00:01:00+00:00")
        elif drift == "key":
            key[0] = "d" * 64
        elif drift == "record":
            resources.rows.append(_record(queued.target_id))
        else:
            jobs.save(_active_inspector_job(child, INSPECTION_ACTION, "running"))
        return claimed
    jobs.claim_lease = claim_and_drift
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id).input["phase"] == "awaiting_inspector_preflight"
    assert len(jobs.get(child.id).events) == 4


def test_default_key_reader_requires_existing_safe_files(tmp_path, monkeypatch):
    key_dir = tmp_path / "inspector-keys"
    key_dir.mkdir(mode=0o700)
    monkeypatch.setattr(service, "_inspector_key_dir", lambda: key_dir)
    private = key_dir / "id_ed25519"
    public = key_dir / "id_ed25519.pub"
    with pytest.raises(FileNotFoundError):
        service._existing_key_fingerprint()
    private.write_text("private fixture", encoding="utf-8")
    private.chmod(0o600)
    value = b"ssh-ed25519 AAAATEST fixture\n"
    public.write_bytes(value)
    public.chmod(0o644)
    assert service._existing_key_fingerprint() == hashlib.sha256(value.strip()).hexdigest()
    public.unlink()
    public.symlink_to(private)
    with pytest.raises(ValueError):
        service._existing_key_fingerprint()


def test_postclaim_settings_drift_leaves_no_intent(tmp_path):
    jobs, queued, _scope, _plans, child, settings, _resources, _credentials, _key, options = _case(tmp_path)
    settings.after_read = lambda holder: setattr(holder, "row", replace(holder.row, size="g6-standard-1")) if holder.reads == 2 else None
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert len(jobs.get(child.id).events) == 4
    # No create event was consumed. After the claim expires and settings are
    # restored, a new claim may still reserve the one-shot intent.
    settings.after_read = None
    settings.row = replace(settings.row, size="g6-nanode-1")
    current = jobs.get(child.id)
    jobs.save(replace(current, input={**current.input,
                                     "claimExpiresAt": "2026-10-08T00:00:00+00:00"}))
    options["token_factory"] = lambda: "g" * 32
    assert service.reserve_keyed_inspector_create_intent(queued.id, **options).resource_name.startswith("inspector-")


def test_postcas_record_drift_consumes_intent_and_returns_attention(tmp_path):
    jobs, queued, _scope, _plans, child, _settings, resources, _credentials, _key, options = _case(tmp_path)
    resources.after_read = lambda holder: holder.rows.append(_record(queued.target_id)) if holder.reads == 3 else None
    with pytest.raises(service.ProviderKeyedInspectorCreateAttention):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id).input["phase"] == "inspector_create_started"
    assert len(jobs.get(child.id).events) == 5


def test_postcas_lifecycle_job_consumes_intent_and_returns_attention(tmp_path):
    jobs, queued, _scope, _plans, child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    original = jobs.append_keyed_inspector_create_intent_if_running_claimed
    def append_then_concurrent_inspection(*args, **kwargs):
        result = original(*args, **kwargs)
        if result is not None:
            jobs.save(_active_inspector_job(child, INSPECTOR_READINESS_ACTION, "queued"))
        return result
    jobs.append_keyed_inspector_create_intent_if_running_claimed = append_then_concurrent_inspection
    with pytest.raises(service.ProviderKeyedInspectorCreateAttention):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id).input["phase"] == "inspector_create_started"
    assert len(jobs.get(child.id).events) == 5


def test_split_v1_and_wrong_environment_rejected(tmp_path):
    jobs, queued, _scope, _plans, child, _settings, _resources, _credentials, _key, options = _case(tmp_path)
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **{**options, "environment": "prod"})
    core = jobs.get("job-core")
    jobs.save(replace(core, input={**core.input, "sketchStateSchema": "split-v1"}))
    with pytest.raises(service.ProviderKeyedInspectorCreateIntentError):
        service.reserve_keyed_inspector_create_intent(queued.id, **options)
    assert jobs.get(child.id).input["phase"] == "awaiting_inspector_preflight"
