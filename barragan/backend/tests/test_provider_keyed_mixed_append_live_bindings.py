# Copyright (c) 2026, Oracle and/or its affiliates.
"""Complete engagement-scoped live-binding inventory for mixed append."""

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from app.services.provider_keyed_mixed_append_live_bindings import (
    MixedAppendLiveBindingsAttention, collect_mixed_append_live_bindings,
)


@dataclass(frozen=True)
class Row:
    engagement_id: str
    id: str
    status: str
    config: dict
    updated_at: str = "first"

    @property
    def service_id(self):
        return self.id


class Domains:
    def __init__(self, rows):
        self.rows = rows

    def list_assignments(self, *, engagement_id):
        assert engagement_id == "eng-one"
        return self.rows


class Certificates:
    def __init__(self, assets, bindings):
        self.assets = assets
        self.bindings = bindings

    def list_assets(self, engagement_id):
        assert engagement_id == "eng-one"
        return self.assets

    def list_bindings(self, engagement_id):
        assert engagement_id == "eng-one"
        return self.bindings


class Services:
    def __init__(self, rows):
        self.rows = rows

    def list_for_engagement(self, engagement_id):
        assert engagement_id == "eng-one"
        return self.rows


class Jobs:
    def __init__(self, inbound, outbound):
        self.inbound = inbound
        self.outbound = outbound
        self.extra = []

    def list_channel_mutations_for_engagement(self, engagement_id):
        assert engagement_id == "eng-one"
        return [*self.extra,
                _job("job-inbound", "engagement_channels_update",
                     {"inboundChannels": self.inbound}),
                _job("job-outbound", "engagement_channels_update",
                     {"outboundChannels": self.outbound})]


def _job(identifier, action, data):
    return SimpleNamespace(id=identifier, action=action, status="succeeded",
        input={"engagementId": "eng-one"}, events=[
            SimpleNamespace(sequence=1, level="info", message="channels saved",
                            data=data)])


def _case():
    inbound = [{"channelId": "in-1", "edge": "one",
                "customTransport": {"exactRawFieldAbsentFromUiProjection": "kept"}}]
    outbound = [{"channelId": "out-1", "edge": "two"}]
    jobs = Jobs(inbound, outbound)
    assignments = [Row("eng-one", "assignment-1", "active", {"domain": "one"})]
    ownership = [Row("eng-one", "dns-1", "active", {"record": "one"})]
    assets = [Row("eng-one", "cert-1", "issued", {"version": "one"})]
    bindings = [Row("eng-one", "binding-1", "bound", {"channel": "in-1"})]
    services = [Row("eng-one", "site-1", "ready", {"proxy": "proxy01"})]
    options = dict(
        job_repository=jobs,
        domain_repository=Domains(assignments),
        dns_ownership_reader=lambda engagement: ownership,
        certificate_repository=Certificates(assets, bindings),
        service_repository=Services(services),
    )
    return jobs, assignments, ownership, assets, bindings, services, options


def test_complete_snapshot_is_opaque_and_stable_without_timestamp_changes():
    jobs, assignments, _, _, _, _, options = _case()
    before = collect_mixed_append_live_bindings("eng-one", **options)
    assert set(before) == {"channels", "domains", "certificates", "sites"}
    assert tuple(len(before[key]) for key in before) == (2, 2, 2, 1)
    assert "proxy01" not in repr(before)
    assert "record" not in repr(before)
    assignments[0] = Row("eng-one", "assignment-1", "active",
                         {"domain": "one"}, updated_at="later")
    jobs.inbound[0]["checkedAt"] = "later"
    assert collect_mixed_append_live_bindings("eng-one", **options) == before
    jobs.inbound[0]["customTransport"]["exactRawFieldAbsentFromUiProjection"] = "changed"
    assert collect_mixed_append_live_bindings("eng-one", **options) != before


@pytest.mark.parametrize("category", [
    "inbound", "outbound", "assignment", "dns", "asset", "binding", "service",
])
def test_same_count_substitution_changes_complete_snapshot(category):
    jobs, assignments, ownership, assets, bindings, services, options = _case()
    before = collect_mixed_append_live_bindings("eng-one", **options)
    if category in {"inbound", "outbound"}:
        rows = jobs.inbound if category == "inbound" else jobs.outbound
        rows[0]["edge"] = "different"
    else:
        rows = {"assignment": assignments, "dns": ownership,
                "asset": assets, "binding": bindings, "service": services}[category]
        old = rows[0]
        rows[0] = Row("eng-one", old.id, old.status, {"changed": True})
    after = collect_mixed_append_live_bindings("eng-one", **options)
    assert tuple(map(len, before.values())) == tuple(map(len, after.values()))
    assert before != after


def test_disappearing_row_changes_snapshot():
    _, _, ownership, _, _, _, options = _case()
    before = collect_mixed_append_live_bindings("eng-one", **options)
    ownership.clear()
    after = collect_mixed_append_live_bindings("eng-one", **options)
    assert before != after
    assert len(after["domains"]) == len(before["domains"]) - 1


def test_other_engagement_row_fails_closed():
    _, _, ownership, _, _, _, options = _case()
    ownership[0] = Row("eng-two", "dns-1", "active", {})
    with pytest.raises(MixedAppendLiveBindingsAttention):
        collect_mixed_append_live_bindings("eng-one", **options)


def test_b_update_is_not_hidden_by_later_a_snapshot_with_stale_b():
    jobs, _, _, _, _, _, options = _case()
    b_update = _job("job-b-update", "outbound_channel_apply", {
        "outboundChannels": [
            {"channelId": "A", "edge": "original"},
            {"channelId": "B", "edge": "new-B"},
        ]})
    a_stale = _job("job-a-later", "outbound_channel_apply", {
        "outboundChannels": [
            {"channelId": "A", "edge": "new-A"},
            {"channelId": "B", "edge": "old-B"},
        ]})
    jobs.extra = [a_stale, b_update]
    before = collect_mixed_append_live_bindings("eng-one", **options)
    b_update.events[0].data["outboundChannels"][1]["edge"] = "different-B"
    after = collect_mixed_append_live_bindings("eng-one", **options)
    assert before != after
    assert len(before["channels"]) == len(after["channels"])


def test_mixed_default_backflip_row_is_excluded_but_real_row_is_fenced():
    jobs, _, _, _, _, _, options = _case()
    default = {"channelId": "default-backflip", "service": "backflips",
               "status": "pending"}
    real = {"channelId": "real", "service": "listener", "edge": "one"}
    jobs.extra = [_job("job-mixed", "inbound_channel_apply", {
        "inboundChannels": [default, real]})]
    before = collect_mixed_append_live_bindings("eng-one", **options)
    default["status"] = "changed-synthetic"
    assert collect_mixed_append_live_bindings("eng-one", **options) == before
    real["edge"] = "two"
    assert collect_mixed_append_live_bindings("eng-one", **options) != before
    jobs.extra.append(_job("job-inspector", "inspector_inspection", {
        "inboundChannels": [{"channelId": "old-snapshot"}]}))
    after_real_change = collect_mixed_append_live_bindings("eng-one", **options)
    jobs.extra[-1].events[0].data["inboundChannels"][0]["channelId"] = "new-snapshot"
    assert collect_mixed_append_live_bindings("eng-one", **options) == after_real_change
    jobs.extra.append(_job("job-synthetic", "backflips_service_apply", {
        "inboundChannels": [default]}))
    assert collect_mixed_append_live_bindings("eng-one", **options) == after_real_change


def test_channel_removal_action_without_snapshot_changes_history():
    jobs, _, _, _, _, _, options = _case()
    before = collect_mixed_append_live_bindings("eng-one", **options)
    jobs.extra.append(_job("job-remove", "inbound_channel_remove", {
        "channelId": "in-1", "status": "removed"}))
    assert collect_mixed_append_live_bindings("eng-one", **options) != before


@pytest.mark.parametrize("backend", ["sqlalchemy", "sqlite"])
def test_targeted_channel_history_keeps_mutations_but_skips_unrelated_jobs(tmp_path, backend):
    from app import create_app
    from app.core.config import TestConfig
    from app.domain import JobEvent
    from app.storage.job_repository import (
        SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun,
    )
    from app.services.provider_keyed_mixed_append_live_bindings import _channel_history

    class Config(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'jobs-sqlalchemy.sqlite'}"

    app = create_app(Config)
    with app.storage_context():
        repository = (SqlAlchemyJobRepository() if backend == "sqlalchemy"
                      else SqliteJobRepository(tmp_path / "jobs-sqlite.sqlite"))

        def save(identifier, action, data, engagement="eng-one"):
            repository.save(StoredJobRun(
                id=identifier, action=action, status="succeeded",
                target=f"engagement:{engagement}", target_type="engagement",
                target_id=engagement, requested_by="operator",
                input={"engagementId": engagement}, artifact_refs=[],
                created_at="2026-10-19T00:00:00+00:00", started_at=None,
                finished_at=None, events=[JobEvent(1, "info", "event", data)],
            ))

        for number in range(40):
            save(f"unrelated-{number}", "provider_inventory_read", {"count": number})
        save("snapshot", "custom_channel_writer", {"inboundChannels": [{"channelId": "in-1"}]})
        save("removal", "outbound_channel_remove", {"channelId": "out-1"})
        save("inspector", "inspector_inspection", {"outboundChannels": [{"channelId": "old"}]})
        save("other-engagement", "inbound_channel_apply", {"inboundChannels": []}, "eng-two")

        selected = repository.list_channel_mutations_for_engagement("eng-one")
        assert {job.id for job in selected} == {"snapshot", "removal", "inspector"}
        assert _channel_history(selected) == _channel_history(
            repository.list_for_engagement("eng-one"))
        assert {job.id for job in repository.list_for_engagement("eng-one")} >= {
            "snapshot", "removal", "inspector", "unrelated-0",
        }
