# Copyright (c) 2026, Oracle and/or its affiliates.
"""File-backed local terminal composition with an explicit source-proof seam.

The Linode one-shot provider transport, SQLite jobs/resources/settings/lifecycle,
and terminal transaction are real. Earlier keyed source recognizers are
injected because their existing fixtures do not share one sealed generation;
this is not a full canonical source-to-provider acceptance proof.
"""

from dataclasses import replace

import pytest

from app.services import provider_keyed_inspector_linode_cleanup as cleanup
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel, EngagementModel
from app.storage.engagement_lifecycle_repository import SqlAlchemyEngagementLifecycleRepository
from app.storage.observer_settings_repository import SqlAlchemyObserverSettingsRepository
from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
from test_provider_keyed_inspector_linode_cleanup import _Cloud, _durable_case


def _case(tmp_path, monkeypatch):
    state, parent, preview = _durable_case(tmp_path, monkeypatch)
    with db.bind(state):
        jobs = SqlAlchemyJobRepository()
        selector = jobs.get("job-provider-keyed-selector-retirement-core")
        oci = jobs.get("job-provider-keyed-core-destroy-absence-core-attempt-01")
        engagement = EngagementModel.query.get(parent.target_id)
        engagement.input_parameters = {"desired": "preserved"}
        db.session.commit()
    return state, parent, preview, selector, oci


def _run(state, parent, preview, selector, oci, cloud, tmp_path, *, calls=None,
         selector_fails=False):
    calls = calls if calls is not None else []

    def selector_reader(*_args, **_kwargs):
        calls.append(("selector", len(cloud.deletes)))
        if selector_fails:
            raise ValueError("incomplete DigitalOcean visibility")
        return SqlAlchemyJobRepository().get(selector.id)

    def group_reader(*_args, **_kwargs):
        calls.append(("group", len(cloud.deletes)))
        return ("retired-chain-1", "retired-chain-2")

    def oci_reader(*_args, **_kwargs):
        calls.append(("oci", len(cloud.deletes)))
        return SqlAlchemyJobRepository().get(oci.id)

    def negative_reader(*_args, **_kwargs):
        calls.append(("negative", len(cloud.deletes)))
        return SqlAlchemyJobRepository().get(preview.negative_job_id)

    with db.bind(state):
        return cleanup.retire_pending_linode_inspector(
            parent.id, environment="devtest", state_root=tmp_path,
            read_transport=cloud, delete_transport=cloud,
            decrypt_secret=lambda _: "plaintext-token", sleep=lambda _: None,
            preview_reader=lambda *_a, **_k: preview,
            readiness_reader=lambda *_a, **_k: type("Ready", (), {
                "host_record_id": preview.host_record_id,
                "firewall_record_id": preview.firewall_record_id})(),
            group_reader=group_reader, oci_reader=oci_reader,
            selector_reader=selector_reader, negative_reader=negative_reader,
            selector_catalog_transport=object(), selector_status_transport=object(),
        )


def test_selector_visibility_vetoes_linode_delete_before_intent(tmp_path, monkeypatch):
    state, parent, preview, selector, oci = _case(tmp_path, monkeypatch)
    cloud = _Cloud()
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run(state, parent, preview, selector, oci, cloud, tmp_path,
             selector_fails=True)
    assert cloud.deletes == []
    with db.bind(state):
        assert SqlAlchemyJobRepository().get(parent.id).status == "queued"
        assert SqlAlchemyJobRepository().get(
            "job-provider-keyed-inspector-linode-cleanup-core") is None


def test_local_terminal_rollback_then_restart_without_delete_replay(tmp_path, monkeypatch):
    state, parent, preview, selector, oci = _case(tmp_path, monkeypatch)
    cloud = _Cloud()
    calls = []
    with db.bind(state):
        resources = SqlAlchemyProviderResourceRepository()
        host = resources.get(preview.host_record_id)
        residual = resources.save(replace(
            host, id="digitalocean:owned-residual", provider="digitalocean",
            resource_type="droplet", resource_id="888", name="opaque-residual",
            source="barragan", adoption_job_id="job-fixture",
            metadata={"barraganOwned": True, "role": "sketch"},
        ))
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run(state, parent, preview, selector, oci, cloud, tmp_path, calls=calls)
    assert cloud.deletes == ["/linode/instances/12345", "/networking/firewalls/67890"]
    assert ("selector", 0) in calls
    assert ("selector", 2) in calls
    with db.bind(db.configure(state.uri)):
        jobs = SqlAlchemyJobRepository()
        assert jobs.get(parent.id).status == "queued"
        assert jobs.get(cleanup._child_id("job-core")).input["phase"] == "pending_group_retired"
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).enabled is True
        assert SqlAlchemyProviderResourceRepository().get(preview.host_record_id).status == "active"
        lease = CoreMutationLeaseModel.query.get(parent.target_id)
        assert (lease.owner_id, lease.operation) == ("plan-core", cleanup._FENCE)
        resources = SqlAlchemyProviderResourceRepository()
        resources.save(replace(resources.get(residual.id), status="destroyed",
                               lifecycle_state="destroyed", destroyed_at="2026-10-09T00:00:03+00:00"))
    result = _run(db.configure(state.uri), parent, preview, selector, oci,
                  cloud, tmp_path, calls=calls)
    assert result.status == "succeeded"
    assert cloud.deletes == ["/linode/instances/12345", "/networking/firewalls/67890"]
    with db.bind(db.configure(state.uri)):
        jobs = SqlAlchemyJobRepository()
        assert jobs.get(parent.id).status == "succeeded"
        assert jobs.get(cleanup._child_id("job-core")).status == "succeeded"
        assert CoreMutationLeaseModel.query.get(parent.target_id) is None
        assert SqlAlchemyObserverSettingsRepository().get(parent.target_id).enabled is False
        assert SqlAlchemyProviderResourceRepository().get(preview.host_record_id).status == "destroyed"
        assert EngagementModel.query.get(parent.target_id).input_parameters == {
            "desired": "preserved"}
        lifecycle = SqlAlchemyEngagementLifecycleRepository()
        assert lifecycle.get(parent.target_id).state == "destroyed"
        assert cleanup.recognize_pending_linode_inspector_retired(
            parent.id, environment="devtest") == result


def test_wrong_keyed_lease_is_never_released(tmp_path, monkeypatch):
    state, parent, preview, selector, oci = _case(tmp_path, monkeypatch)
    cloud = _Cloud()
    with db.bind(state):
        lease = CoreMutationLeaseModel.query.get(parent.target_id)
        lease.owner_id = "different-core-plan"
        db.session.commit()
    with pytest.raises(cleanup.LinodeInspectorCleanupAttention):
        _run(state, parent, preview, selector, oci, cloud, tmp_path)
    with db.bind(db.configure(state.uri)):
        lease = CoreMutationLeaseModel.query.get(parent.target_id)
        assert (lease.owner_id, lease.operation) == (
            "different-core-plan", cleanup._FENCE)
        assert SqlAlchemyJobRepository().get(parent.id).status == "queued"
