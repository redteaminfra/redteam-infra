# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private Linode Inspector cleanup preview is read-only and identity-fenced."""

from dataclasses import replace
import hashlib
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_inspector_linode_cleanup as cleanup
from app.services.observer_checks import INSPECTOR_RESOURCE_SOURCE, _inspector_firewall_label
from app.storage import models as _models  # noqa: F401
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun, job_event_digest
from app.storage.observer_settings_repository import StoredInspectorSettings, SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import StoredProviderResourceRecord, SqlAlchemyProviderResourceRepository
from app.storage.credential_repository import StoredCredential, SqlAlchemyCredentialRepository
from app.integrations.linode_validation import LinodeValidationError
import urllib.error


def _job(identifier, action, status, engagement, input_data, events):
    return StoredJobRun(identifier, action, status, f"engagement:{engagement}",
                        "engagement", engagement, "operator", input_data, [],
                        "2026-10-09T00:00:00+00:00", "2026-10-09T00:00:01+00:00",
                        "2026-10-09T00:00:02+00:00" if status == "succeeded" else None,
                        events)


def _case(tmp_path, monkeypatch):
    engagement = "eng-disposable"
    parent = _job("job-parent", "engagement_teardown", "queued", engagement,
                  {}, [JobEvent(1, "info", "engagement teardown queued", {})])
    core = _job("job-core", "pilot_standard_rti", "succeeded", engagement,
                {"corePlanId": "plan-core"}, [])
    secret = "encrypted-test-value"
    credential = SimpleNamespace(id="selected-credential", provider="linode",
                                 alias="selected", status="active", is_default=False,
                                 updated_at="2026-10-09T00:00:00+00:00",
                                 encrypted_secret=secret)
    intent = {"provider": "linode", "resourceName": "inspector-opaque",
              "scopeSnapshotId": "a" * 64, "credentialId": credential.id,
              "credentialAlias": credential.alias,
              "credentialUpdatedAt": credential.updated_at,
              "credentialSha256": hashlib.sha256(secret.encode()).hexdigest(),
              "managementSourceCidr": "1.1.1.1/32"}
    coordinator = _job(cleanup._child_id(core.id),
                       "provider_keyed_comprehensive_teardown", "running", engagement,
                       {"phase": "pending_group_retired"},
                       [JobEvent(1, "info", "inspector_create_started", intent)])
    negative = _job("job-provider-keyed-inspector-negative-core",
                    cleanup.NEGATIVE_ACTION, "succeeded", engagement,
                    {"teardownParentId": parent.id, "coreJobId": core.id,
                     "scopeSnapshotId": "a" * 64,
                     "positiveControl": {"id": "inspector-external-control", "type": "tcp",
                                         "host": "1.1.1.1", "port": 443}},
                    [JobEvent(1, "info", "inspector negative queued", {}),
                     JobEvent(2, "info", "inspector negative started", {}),
                     JobEvent(3, "info", "inspector exact public negative proved", {})])
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    for row in (parent, core, coordinator, negative):
        jobs.save(row)
    snapshot = {"snapshotId": "a" * 64}
    monkeypatch.setattr(cleanup, "_boundary", lambda *_: (
        jobs.get(parent.id), jobs.get(core.id), snapshot, cleanup._FENCE))
    host = {"provider": "linode", "resourceType": "instance", "resourceId": "12345",
            "name": "inspector-opaque", "region": "us-sea", "publicIp": "8.8.8.8",
            "metadata": {"providerFirewall": {"resourceId": "67890",
                                               "managementSourceCidr": "1.1.1.1/32"}}}
    settings = SimpleNamespace(current_host=host, enabled=True, provider="linode", size="g6-nanode-1",
                               region="us-sea")
    settings_repo = SimpleNamespace(get=lambda _: settings)
    host_row = SimpleNamespace(id="linode:inspector:12345", engagement_id=engagement,
                               source=INSPECTOR_RESOURCE_SOURCE, provider="linode",
                               resource_type="inspector_instance", resource_id="12345",
                               name="inspector-opaque", region="us-sea", status="active",
                               adoption_job_id=coordinator.id,
                               metadata={"barraganOwned": True, "role": "inspector"})
    firewall_row = SimpleNamespace(id="linode:inspector-firewall:67890", engagement_id=engagement,
                                   source=INSPECTOR_RESOURCE_SOURCE, provider="linode",
                                   resource_type="inspector_firewall", resource_id="67890",
                                   name=_inspector_firewall_label("linode", "inspector-opaque"),
                                   region="us-sea", status="active",
                                   adoption_job_id=coordinator.id,
                                   metadata={"barraganOwned": True, "role": "inspector_firewall"})
    rows = [host_row, firewall_row]
    resources = SimpleNamespace(list_for_engagement=lambda _: list(rows),
                                get=lambda identifier: next((row for row in rows if row.id == identifier), None))
    credential_rows = [credential]
    credentials = SimpleNamespace(get=lambda identifier: next(
        (row for row in credential_rows if row.id == identifier), None))
    calls = []

    class Transport:
        def request(self, method, path, token):
            calls.append((method, path, token))
            assert method == "GET"
            if path.startswith("/linode/instances?"):
                return {"data": [{"id": 12345}], "page": 1, "pages": 1, "results": 1}
            if path.startswith("/networking/firewalls?"):
                return {"data": [{"id": 67890}], "page": 1, "pages": 1, "results": 1}
            raise AssertionError(path)

    def provider_proof(_client, token, **kwargs):
        calls.append(("proof", kwargs, token))
        return SimpleNamespace(host=SimpleNamespace(public_ip="8.8.8.8"))

    monkeypatch.setattr(cleanup, "_linode", provider_proof)
    options = dict(environment="devtest", state_root=tmp_path,
                   job_repository=jobs, plan_repository=SimpleNamespace(),
                   settings_repository=settings_repo, provider_resource_repository=resources,
                   credential_repository=credentials,
                   lease_lookup=lambda _: ("plan-core", cleanup._FENCE),
                   transport=Transport(), decrypt_secret=lambda value: "plaintext-token" if value == secret else "",
                   readiness_recognizer=lambda *_a, **_k: SimpleNamespace(
                       host_record_id=host_row.id, firewall_record_id=firewall_row.id),
                   negative_recognizer=lambda *_a, **_k: jobs.get(negative.id))
    return parent, negative, coordinator, credential_rows, rows, jobs, calls, options


def test_file_backed_preview_selects_creation_credential_without_mutation(tmp_path, monkeypatch):
    parent, negative, coordinator, _credentials, _rows, jobs, calls, options = _case(tmp_path, monkeypatch)
    result = cleanup.preview_pending_linode_inspector_cleanup(parent.id, **options)
    assert result.credential_id == "selected-credential"
    assert result.host_id == "12345" and result.firewall_id == "67890"
    assert result.negative_job_id == negative.id
    assert result.coordinator_job_id == coordinator.id
    assert all(call[0] in {"GET", "proof"} for call in calls)
    assert SqliteJobRepository(jobs.database_path).get(negative.id) == negative
    assert SqliteJobRepository(jobs.database_path).get(coordinator.id) == coordinator


@pytest.mark.parametrize("drift", ["rotated", "missing_receipt", "extra_firewall", "wrong_owner",
                                   "negative_failed", "readiness_wrong"])
def test_preview_fails_closed_on_identity_drift(tmp_path, monkeypatch, drift):
    parent, negative, coordinator, credentials, rows, jobs, calls, options = _case(tmp_path, monkeypatch)
    if drift == "rotated":
        credentials[0] = SimpleNamespace(**{**vars(credentials[0]), "encrypted_secret": "rotated"})
    elif drift == "missing_receipt":
        event = coordinator.events[0]
        jobs.save(replace(coordinator, events=[replace(event, data={
            key: value for key, value in event.data.items() if key != "credentialSha256"})]))
    elif drift == "extra_firewall":
        rows.append(SimpleNamespace(**{**vars(rows[1]), "id": "linode:inspector-firewall:99999"}))
    elif drift == "wrong_owner":
        rows[1] = SimpleNamespace(**{**vars(rows[1]), "metadata": {"role": "inspector_firewall"}})
    elif drift == "negative_failed":
        jobs.save(replace(negative, status="failed"))
    else:
        options["readiness_recognizer"] = lambda *_a, **_k: SimpleNamespace(
            host_record_id="wrong", firewall_record_id=rows[1].id)
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        cleanup.preview_pending_linode_inspector_cleanup(parent.id, **options)
    assert calls == []


@pytest.mark.parametrize("body", [
    {"data": [{"id": 1}], "page": 1, "pages": 1, "results": 2},
    {"data": [{"id": 1}, {"id": 1}], "page": 1, "pages": 1, "results": 2},
    {"data": [], "page": 2, "pages": 1, "results": 0},
])
def test_incomplete_linode_list_visibility_fails_closed(body):
    client = SimpleNamespace(request=lambda *_: body)
    with pytest.raises(ValueError):
        cleanup._complete_ids(client, "token", "/linode/instances")


def _durable_case(tmp_path, monkeypatch):
    from app.domain.deployment_plan import DeploymentPlan
    from app.services.engagement_teardown import ENGAGEMENT_TEARDOWN_ACTION
    from app.services.engagement_teardown import _fingerprint as snapshot_fingerprint
    from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
    from app.storage.models import CoreMutationLeaseModel, EngagementModel

    state = db.configure(f"sqlite:///{tmp_path / 'linode-cleanup.sqlite'}")
    with db.bind(state):
        db.create_all()
        jobs = SqlAlchemyJobRepository()
        engagement = "eng-disposable"
        snapshot = {"providerScopes": [{"corePlanId": "plan-core"}]}
        snapshot["snapshotId"] = snapshot_fingerprint(snapshot)
        parent = replace(_job("job-parent", ENGAGEMENT_TEARDOWN_ACTION, "queued", engagement,
                      {"phase": "queued", "mutation": True, "coreJobId": "job-core",
                       "scopeSnapshot": snapshot},
                      [JobEvent(1, "info", "engagement teardown queued",
                                {"snapshotId": snapshot["snapshotId"]})]),
                         started_at=None)
        core = replace(_job("job-core", "pilot_standard_rti", "succeeded", engagement,
                    {"corePlanId": "plan-core", "engagementId": engagement}, []),
                       target_type="oci_compartment",
                       target="oci-compartment:barragan-testing",
                       target_id="compartment-fixture")
        secret = "encrypted-test-value"
        intent = {"provider": "linode", "resourceName": "inspector-opaque",
                  "scopeSnapshotId": snapshot["snapshotId"], "credentialId": "selected-credential",
                  "credentialAlias": "selected", "credentialUpdatedAt": "2026-10-09T00:00:00",
                  "credentialSha256": hashlib.sha256(secret.encode()).hexdigest(),
                  "managementSourceCidr": "1.1.1.1/32"}
        coordinator = _job(cleanup._child_id(core.id),
                           "provider_keyed_comprehensive_teardown", "running", engagement,
                           {"phase": "pending_group_retired"},
                           [JobEvent(1, "info", "inspector_create_started", intent)])
        negative = _job("job-provider-keyed-inspector-negative-core", cleanup.NEGATIVE_ACTION,
                        "succeeded", engagement,
                        {"teardownParentId": parent.id, "coreJobId": core.id,
                         "scopeSnapshotId": snapshot["snapshotId"]},
                        [JobEvent(1, "info", "inspector negative queued", {}),
                         JobEvent(2, "info", "inspector negative started", {}),
                         JobEvent(3, "info", "inspector exact public negative proved", {})])
        for row in (parent, core, coordinator, negative):
            jobs.save(row)
        firewall_name = _inspector_firewall_label("linode", "inspector-opaque")
        firewall_meta = {"resourceId": "67890", "name": firewall_name,
                         "managementSourceCidr": "1.1.1.1/32"}
        host = {"provider": "linode", "resourceType": "instance", "resourceId": "12345",
                "name": "inspector-opaque", "region": "us-sea", "publicIp": "8.8.8.8",
                "metadata": {"providerFirewall": firewall_meta}}
        settings = StoredInspectorSettings(
            engagement, True, "linode", "us-sea", "g6-nanode-1", "continuous",
            [], "00:00", [], [], [], host, "", "", "", "2026-10-09T00:00:00+00:00",
            "2026-10-09T00:00:00+00:00")
        settings_repo = SqlAlchemyObserverSettingsRepository()
        settings_repo.save(settings)
        resources = SqlAlchemyProviderResourceRepository()
        common = dict(engagement_id=engagement, engagement_name="disposable",
                      provider="linode", region="us-sea", lifecycle_state="active",
                      status="active", source=INSPECTOR_RESOURCE_SOURCE,
                      adoption_job_id=coordinator.id,
                      adopted_at="2026-10-09T00:00:00+00:00",
                      updated_at="2026-10-09T00:00:00+00:00")
        resources.save(StoredProviderResourceRecord(
            id="linode:inspector:12345", resource_type="inspector_instance",
            resource_id="12345", name="inspector-opaque",
            metadata={"barraganOwned": True, "role": "inspector",
                      "providerFirewall": firewall_meta}, **common))
        resources.save(StoredProviderResourceRecord(
            id="linode:inspector-firewall:67890", resource_type="inspector_firewall",
            resource_id="67890", name=firewall_name,
            metadata={"barraganOwned": True, "role": "inspector_firewall",
                      "inspectorHostResourceId": "12345",
                      "managementSourceCidr": "1.1.1.1/32"}, **common))
        credentials = SqlAlchemyCredentialRepository()
        stored_credential = credentials.save(StoredCredential(
            "selected-credential", "linode", "selected", "active", "", secret,
            False, "2026-10-09T00:00:00+00:00", "2026-10-09T00:00:00+00:00"))
        intent["credentialUpdatedAt"] = stored_credential.updated_at
        coordinator = replace(coordinator, events=[JobEvent(1, "info", "inspector_create_started", intent)])
        jobs.save(coordinator)
        db.session.add(EngagementModel(
            id=engagement, name="disposable", status="active", owner="operator",
            template_id="standard-rti", input_parameters={},
            sketch_state_schema="provider-keyed-v2"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id=engagement, owner_id="plan-core", operation=cleanup._FENCE))
        db.session.commit()
        SqlAlchemyDeploymentPlanRepository().save(DeploymentPlan(
            "plan-core", engagement, "fixture-revision", "applied", "applied",
            evidence={"target": {"name": "barragan-testing",
                                 "compartmentId": "compartment-fixture"}},
            created_at=core.created_at, updated_at=core.created_at,
            apply_job_id=core.id))
        now = core.created_at
        selector = jobs.save(StoredJobRun(
            "job-provider-keyed-selector-retirement-core", "provider_keyed_selector_retirement", "succeeded",
            parent.target, parent.target_type, engagement, parent.requested_by,
            {"teardownParentId": parent.id, "coreJobId": core.id,
             "corePlanId": "plan-core", "scopeSnapshotId": snapshot["snapshotId"]},
            [], now, now, now,
            [JobEvent(1, "info", "fixture selector receipt", {})]))
        jobs.save(StoredJobRun(
            "job-provider-keyed-core-destroy-absence-core-attempt-01",
            "provider_keyed_core_destroy_absence", "succeeded",
            parent.target, parent.target_type, engagement, parent.requested_by,
            {"teardownParentId": parent.id, "coreJobId": core.id,
             "corePlanId": "plan-core", "scopeSnapshotId": snapshot["snapshotId"]},
            [], now, now, now,
            [JobEvent(1, "info", "fixture OCI receipt", {})]))
        monkeypatch.setattr(cleanup, "_boundary", lambda *_: (
            jobs.get(parent.id), jobs.get(core.id), snapshot, cleanup._FENCE))
        preview = cleanup.LinodeInspectorCleanupPreview(
            parent.id, coordinator.id, negative.id, job_event_digest(negative.events),
            cleanup._negative_input_sha(negative.input),
            job_event_digest(coordinator.events), "selected-credential",
            intent["credentialSha256"], "linode:inspector:12345",
            "linode:inspector-firewall:67890", "12345", "67890")
    return state, parent, preview


class _Cloud:
    def __init__(self, *, crash_on=None, stale_host_list=False, bad_response=False,
                 extra_devices=False):
        self.host = True
        self.firewall = True
        self.crash_on = crash_on
        self.stale_host_list = stale_host_list
        self.bad_response = bad_response
        self.extra_devices = extra_devices
        self.deletes = []

    def request(self, method, path, token):
        assert method == "GET" and token == "plaintext-token"
        if path.startswith("/linode/instances?"):
            data = [{"id": 12345}] if self.host or self.stale_host_list else []
        elif path.startswith("/networking/firewalls?"):
            data = [{"id": 67890}] if self.firewall else []
        elif path.endswith("/devices?page=1&page_size=100"):
            data = [{"id": 99999}] if self.extra_devices else []
        elif path == "/networking/firewalls/67890":
            if self.firewall:
                return {"id": 67890, "label": _inspector_firewall_label("linode", "inspector-opaque")}
            raise LinodeValidationError("404") from urllib.error.HTTPError(path, 404, "", {}, None)
        elif path == "/linode/instances/12345":
            if self.host:
                return {"id": 12345}
            raise LinodeValidationError("404") from urllib.error.HTTPError(path, 404, "", {}, None)
        else:
            raise AssertionError(path)
        return {"data": data, "page": 1, "pages": 1, "results": len(data)}

    def delete(self, path, token):
        self.deletes.append(path)
        if path == "/linode/instances/12345":
            self.host = False
        elif path == "/networking/firewalls/67890":
            self.firewall = False
        else:
            raise AssertionError(path)
        if self.crash_on == path:
            raise RuntimeError("simulated lost provider response")
        return cleanup.LinodeDeleteResponse(200, b"{}x" if self.bad_response else b"{}")


def _run_durable(state, parent, preview, cloud, *, tmp_path):
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        return cleanup.retire_pending_linode_inspector(
            parent.id, environment="devtest", state_root=tmp_path,
            read_transport=cloud, delete_transport=cloud,
            decrypt_secret=lambda _: "plaintext-token", sleep=lambda _: None,
            preview_reader=lambda *_a, **_k: preview,
            readiness_reader=lambda *_a, **_k: SimpleNamespace(
                host_record_id=preview.host_record_id,
                firewall_record_id=preview.firewall_record_id),
            group_reader=lambda *_a, **_k: ("retired-chain-1", "retired-chain-2"),
            oci_reader=lambda *_a, **_k: jobs.get(
                "job-provider-keyed-core-destroy-absence-core-attempt-01"),
            selector_reader=lambda *_a, **_k: jobs.get(
                "job-provider-keyed-selector-retirement-core"),
            negative_reader=lambda *_a, **_k: jobs.get(preview.negative_job_id),
            selector_catalog_transport=object(), selector_status_transport=object())


def test_file_backed_full_cleanup_and_saved_success_restart(tmp_path, monkeypatch):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    cloud = _Cloud()
    result = _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert result.status == "succeeded"
    assert cloud.deletes == ["/linode/instances/12345", "/networking/firewalls/67890"]
    with db.bind(state):
        assert cleanup.recognize_pending_linode_inspector_retired(
            parent.id, environment="devtest") == result
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).current_host == {}
        assert all(row.status == "destroyed" for row in
                   SqlAlchemyProviderResourceRepository().list_for_engagement(parent.target_id))
    assert _run_durable(state, parent, preview, cloud, tmp_path=tmp_path) == result
    assert len(cloud.deletes) == 2


@pytest.mark.parametrize("field,value", [
    ("positiveControl", {"id": "inspector-external-control", "type": "tcp",
                         "host": "4.2.2.2", "port": 443}),
    ("freshDigitalOceanAbsenceSha256", "f" * 64),
])
def test_retired_inspector_rejects_negative_input_drift_with_same_event_digest(
        tmp_path, monkeypatch, field, value):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    _run_durable(state, parent, preview, _Cloud(), tmp_path=tmp_path)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        negative = jobs.get(preview.negative_job_id)
        jobs.save(replace(negative, input={**negative.input, field: value}))
        with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
            cleanup.recognize_pending_linode_inspector_retired(
                parent.id, environment="devtest")


@pytest.mark.parametrize("crash_on", ["/linode/instances/12345", "/networking/firewalls/67890"])
def test_file_backed_crash_after_go_never_replays_delete(tmp_path, monkeypatch, crash_on):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    cloud = _Cloud(crash_on=crash_on)
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    cloud.crash_on = None
    result = _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert result.status == "succeeded"
    assert cloud.deletes.count(crash_on) == 1


def test_terminal_recognizer_rejects_missing_intent(tmp_path, monkeypatch):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    result = _run_durable(state, parent, preview, _Cloud(), tmp_path=tmp_path)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        current = jobs.get(result.id)
        jobs.save(replace(current, events=[event for event in current.events
                                           if event.message != "inspector firewall DELETE intended"]))
        with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
            cleanup.recognize_pending_linode_inspector_retired(parent.id, environment="devtest")


@pytest.mark.parametrize("source_id", [
    "job-provider-keyed-core-destroy-absence-core-attempt-01",
    "job-provider-keyed-selector-retirement-core",
])
def test_terminal_recognizer_rejects_source_action_tamper(tmp_path, monkeypatch, source_id):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    _run_durable(state, parent, preview, _Cloud(), tmp_path=tmp_path)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        source = jobs.get(source_id)
        jobs.save(replace(source, action="unrelated_action"))
        with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
            cleanup.recognize_pending_linode_inspector_retired(
                parent.id, environment="devtest")


def test_terminal_recognizer_tolerates_later_generation_fence(tmp_path, monkeypatch):
    from app.storage.models import CoreMutationLeaseModel

    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    result = _run_durable(state, parent, preview, _Cloud(), tmp_path=tmp_path)
    with db.bind(state):
        db.session.add(CoreMutationLeaseModel(
            engagement_id=parent.target_id, owner_id="later-plan",
            operation="another_generation"))
        db.session.commit()
        assert cleanup.recognize_pending_linode_inspector_retired(
            parent.id, environment="devtest") == result


@pytest.mark.parametrize("source_id", [
    "job-provider-keyed-core-destroy-absence-core-attempt-01",
    "job-provider-keyed-selector-retirement-core",
])
def test_source_input_race_before_terminal_writer_rolls_back(tmp_path, monkeypatch, source_id):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    finish = cleanup._finish_atomic

    def drift_before_writer(*args, **kwargs):
        jobs = kwargs["jobs"]
        source = jobs.get(source_id)
        jobs.save(replace(source, input={**source.input, "changedAfterProof": True}))
        return finish(*args, **kwargs)

    monkeypatch.setattr(cleanup, "_finish_atomic", drift_before_writer)
    cloud = _Cloud()
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert cloud.deletes == ["/linode/instances/12345", "/networking/firewalls/67890"]
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(parent.id).status == "queued"
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).enabled is True
        assert SqlAlchemyProviderResourceRepository().get(preview.host_record_id).status == "active"


def test_get404_without_complete_list_absence_never_allows_firewall_go(tmp_path, monkeypatch):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    cloud = _Cloud(stale_host_list=True)
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert cloud.deletes == ["/linode/instances/12345"]
    with db.bind(state):
        child = SqlAlchemyJobRepository().get("job-provider-keyed-inspector-linode-cleanup-core")
        assert child.status == "running"
        assert "inspector host DELETE intended" in [event.message for event in child.events]
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert cloud.deletes == ["/linode/instances/12345"]


def test_extra_firewall_device_blocks_firewall_delete_after_host(tmp_path, monkeypatch):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    cloud = _Cloud(extra_devices=True)
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert cloud.deletes == ["/linode/instances/12345"]


def test_malformed_persisted_host_intent_never_reaches_firewall_go(tmp_path, monkeypatch):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    cloud = _Cloud(crash_on="/linode/instances/12345")
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        child = jobs.get("job-provider-keyed-inspector-linode-cleanup-core")
        event = child.events[-1]
        assert event.message == "inspector host DELETE intended"
        jobs.save(replace(child, events=[*child.events[:-1], replace(
            event, data={"path": "/linode/instances/99999", "resourceId": "12345"})]))
    cloud.crash_on = None
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run_durable(state, parent, preview, cloud, tmp_path=tmp_path)
    assert cloud.deletes == ["/linode/instances/12345"]
