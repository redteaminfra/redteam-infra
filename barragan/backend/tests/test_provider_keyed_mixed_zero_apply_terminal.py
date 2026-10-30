# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted zero-Apply terminal lifecycle and restart proof."""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_mixed_zero_apply_terminal as service
from app.services import provider_keyed_mixed_zero_apply_inspector_retirement as retirement
from app.services.engagement_lifecycle import resolve_engagement_lifecycle
from app.services.engagement_operations import (
    OperationsReadSnapshot, _teardown_job_summary, get_operations_overview,
)
from app.services.engagement_teardown import _fingerprint, engagement_teardown_in_progress
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.engagement_repository import StoredEngagement
from app.domain import JobEvent
from app.storage.models import (
    CoreMutationLeaseModel, EngagementLifecycleEventModel,
    EngagementLifecycleModel, JobRunModel, ProviderResourceRecordModel,
)
from test_provider_keyed_mixed_zero_apply_inspector_retirement import (
    Provider, _enter_sql, _sql_ready, case,
)


def _retired(case, source, options, state):
    provider = Provider()
    kwargs, jobs, settings, resources = _enter_sql(
        case, source, options, state, provider)
    retired = retirement.retire_mixed_zero_apply_inspector(
        source.engagement_id, source.core_job_id, **kwargs)
    assert retired.status == "succeeded"
    kwargs["lease_lookup"] = _db_lease_lookup
    final = {key: kwargs[key] for key in (
        "environment", "state_root", "core_state_root", "job_repository",
        "plan_repository", "settings_repository", "provider_resource_repository",
        "lease_lookup")}
    final["sketch_repository"] = case.args["sketch_repository"]
    return source, final, jobs, resources, provider


def test_both_provider_orders_finish_once_preserve_configuration_and_restart(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        source, final, jobs, resources, provider = _retired(case, source, options, state)
        assert engagement_teardown_in_progress(source.engagement_id, repository=jobs)
        assert _teardown_job_summary(jobs.get(service._parent_id(source.core_job_id)))[
            "recoveryState"] == "in_progress"
        progress = _teardown_job_summary(
            jobs.get(service._parent_id(source.core_job_id)),
            jobs.list_for_engagement(source.engagement_id))
        assert progress["phase"] == "lifecycle_reconciliation"
        assert progress["progress"] == {"completed": 5, "total": 5}
        assert resolve_engagement_lifecycle(
            source.engagement_id, job_repository=jobs,
            provider_resource_repository=resources,
            sketch_chain_repository=final["sketch_repository"]).state == "tearing_down"
        retired = jobs.get(retirement._child_id(source.core_job_id))
        recorded_digest = retired.input["historicalAuthoritySha256"]
        digests = []
        canonical_digest = service._authority_digest

        def observed_digest(authority):
            digest = canonical_digest(authority)
            digests.append(digest)
            return digest

        monkeypatch.setattr(service, "_authority_digest", observed_digest)
        result = service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final)
        assert digests and set(digests) == {recorded_digest}
        assert result.status == "succeeded"
        assert _teardown_job_summary(result)["recoveryState"] == "complete"
        assert _teardown_job_summary(result)["progress"] == {"completed": 5, "total": 5}
        assert result.input["sourceSha256"] == result.events[0].data["sourceSha256"]
        assert result.input["remainingOwnedResources"] == []
        assert engagement_teardown_in_progress(source.engagement_id, repository=jobs) is None
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=source.engagement_id).count() == 0
        assert db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id=source.engagement_id).one().state == "destroyed"
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=source.engagement_id).count() == 1
        assert resolve_engagement_lifecycle(
            source.engagement_id, job_repository=jobs,
            provider_resource_repository=resources,
            sketch_chain_repository=final["sketch_repository"]).state == "destroyed"
        assert service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final) == result
        assert service.recognize_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, environment="devtest",
            job_repository=jobs, plan_repository=final["plan_repository"],
            settings_repository=final["settings_repository"],
            provider_resource_repository=resources,
            sketch_repository=final["sketch_repository"],
            lease_lookup=_db_lease_lookup) == result
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)

    # New engine/session/repository objects read the saved receipt after release.
    restarted = db.configure(state.uri)
    with db.bind(restarted):
        fresh_jobs = SqlAlchemyJobRepository()
        assert _db_lease_lookup(source.engagement_id) is None
        monkeypatch.setattr(service, "_authority", lambda *_a, **_k: pytest.fail("fence reopened"))
        monkeypatch.setattr(service, "retire_mixed_zero_apply_inspector",
                            lambda *_a, **_k: pytest.fail("retirement replayed"))
        assert service.recognize_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, environment="devtest",
            job_repository=fresh_jobs, plan_repository=final["plan_repository"],
            sketch_repository=final["sketch_repository"]) == result
        assert set(digests) == {recorded_digest}
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


def test_late_residue_rolls_back_parent_lifecycle_and_fence(case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        source, final, jobs, resources, _ = _retired(case, source, options, state)
        chains = final["sketch_repository"]
        rows = chains.list_for_engagement(source.engagement_id)
        chains.list_for_engagement = lambda _: [replace(rows[0], status="failed"), *rows[1:]]
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.finish_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, **final)
        assert jobs.get(service._parent_id(source.core_job_id)).status == "queued"
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=source.engagement_id).count() == 1
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=source.engagement_id).count() == 0


def test_missing_retirement_never_deletes_inspector(case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        provider = Provider()
        kwargs, jobs, settings, resources = _enter_sql(
            case, source, options, state, provider)
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.finish_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id,
                environment="devtest", state_root=case.state_root,
                core_state_root=case.core_state.parents[2],
                job_repository=jobs, plan_repository=kwargs["plan_repository"],
                settings_repository=settings, provider_resource_repository=resources,
                sketch_repository=case.args["sketch_repository"],
                lease_lookup=_db_lease_lookup)
        assert (provider.host_deletes, provider.firewall_deletes) == (0, 0)
        assert jobs.get(service._parent_id(source.core_job_id)).status == "queued"


def test_source_drift_before_terminal_and_after_restart_vetoes(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        source, final, jobs, resources, _ = _retired(case, source, options, state)
        parent = jobs.get(service._parent_id(source.core_job_id))
        jobs.save(replace(parent, input={**parent.input, "sourceSha256": "0" * 64}))
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.finish_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, **final)
        jobs.save(parent)
        done = service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final)
        jobs.save(replace(done, input={**done.input, "sourceSha256": "0" * 64}))
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.recognize_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, environment="devtest",
                job_repository=jobs, plan_repository=final["plan_repository"],
                settings_repository=final["settings_repository"],
                provider_resource_repository=resources,
                sketch_repository=final["sketch_repository"],
                lease_lookup=_db_lease_lookup)


def test_writer_slot_drift_rolls_back_and_historical_drift_vetoes(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        source, final, jobs, resources, _ = _retired(case, source, options, state)
        original = service._residue

        def drift(*args):
            original(*args)
            db.session.query(JobRunModel).filter_by(id=source.core_job_id).update(
                {"status": "failed"})
        monkeypatch.setattr(service, "_residue", drift)
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.finish_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, **final)
        assert jobs.get(source.core_job_id).status == "succeeded"
        assert jobs.get(service._parent_id(source.core_job_id)).status == "queued"
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=source.engagement_id).count() == 1
        monkeypatch.setattr(service, "_residue", original)
        result = service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final)
        db.session.query(JobRunModel).filter_by(id=source.core_job_id).update(
            {"status": "failed"})
        db.session.commit()
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.finish_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, **final)
        assert result.status == "succeeded"


@pytest.mark.parametrize("new_status", ["queued", "succeeded"])
def test_old_terminal_history_survives_later_reviewed_core_generation(
        case, monkeypatch, tmp_path, new_status):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        source, final, jobs, resources, _ = _retired(case, source, options, state)
        old_terminal = service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final)
        old_core = jobs.get(source.core_job_id)
        newer_time = (datetime.fromisoformat(old_terminal.finished_at)
                      + timedelta(seconds=1)).isoformat()
        next_core = replace(
            old_core, id="job-new-core", status=new_status,
            input={**old_core.input, "corePlanId": "plan-new"},
            created_at=newer_time,
            started_at=(newer_time if new_status == "succeeded" else None),
            finished_at=(newer_time if new_status == "succeeded" else None),
            events=([JobEvent(1, "info", "new deployment active", {
                "mutationStatus": "deployed", "finalCleanupStatus": "pending_operator_teardown"})]
                if new_status == "succeeded" else []))
        jobs.save(next_core)
        next_plan = replace(case.plan, id="plan-new", apply_job_id=(
            next_core.id if new_status == "succeeded" else None))
        plans = SimpleNamespace(get=lambda plan_id: next_plan if plan_id == "plan-new"
                                else case.plan if plan_id == case.plan.id else None)
        old_host = next(row for row in resources.list_for_engagement(source.engagement_id)
                        if row.resource_type == "inspector_instance")
        resources.save(replace(
            old_host, id="linode:inspector:101", resource_id="101",
            status="active", lifecycle_state="running", destroyed_at=None,
            adoption_job_id=next_core.id,
            metadata={"barraganOwned": True, "role": "inspector",
                      "publicIp": "5.5.5.5"}))
        settings = final["settings_repository"]
        settings.save(replace(settings.get(source.engagement_id),
                              current_host={"provider": "linode", "resourceId": "101",
                                            "publicIp": "5.5.5.5"}))
        sketches = final["sketch_repository"]
        old_chains = sketches.list_for_engagement(source.engagement_id)
        sketches.list_for_engagement = lambda _: [*old_chains, replace(
            old_chains[0], chain_id="chain-new", status="deployed",
            nodes=[{"hostname": "new-edge"}], deploy_job_id=next_core.id)]
        db.session.add(CoreMutationLeaseModel(
            engagement_id=source.engagement_id, owner_id="plan-new",
            operation="provider_keyed_initial"))
        db.session.commit()
        expected = "deploying" if new_status == "queued" else "active"
        assert resolve_engagement_lifecycle(
            source.engagement_id, job_repository=jobs,
            provider_resource_repository=resources,
            sketch_chain_repository=final["sketch_repository"]).state == expected
        engagement = StoredEngagement(
            id=source.engagement_id, name="opaque-fixture", status="active",
            owner="operator", template_id="small", active_revision=None,
            input_parameters={})
        snapshot = OperationsReadSnapshot(
            jobs={source.engagement_id: jobs.list_for_engagement(source.engagement_id)},
            services={source.engagement_id: []},
            sketch_chains={source.engagement_id: sketches.list_for_engagement(source.engagement_id)},
            provider_records={source.engagement_id: resources.list_for_engagement(source.engagement_id)},
            all_provider_records=resources.list_for_engagement(source.engagement_id),
            lifecycles={}, total_job_count=None, seed_job_exists=False)
        overview = get_operations_overview(
            source.engagement_id,
            engagement_repository=SimpleNamespace(get=lambda _: engagement),
            job_repository=jobs, include_provider_findings=False,
            read_snapshot=snapshot)
        assert overview["teardownJob"] is None
        assert service.recognize_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, environment="devtest",
            job_repository=jobs, plan_repository=plans,
            settings_repository=final["settings_repository"],
            provider_resource_repository=resources,
            sketch_repository=final["sketch_repository"],
            lease_lookup=_db_lease_lookup) == old_terminal
        db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=source.engagement_id).update({"owner_id": "wrong-plan"})
        db.session.commit()
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.recognize_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, environment="devtest",
                job_repository=jobs, plan_repository=plans,
                settings_repository=final["settings_repository"],
                provider_resource_repository=resources,
                sketch_repository=final["sketch_repository"],
                lease_lookup=_db_lease_lookup)


@pytest.mark.parametrize("drift", [
    "core_state_sha256", "core_inventory_sha256", "owned_inspector_record_ids",
    "legacy-source-free-digest",
])
def test_source_bound_history_rejects_drift_after_session_restart(
        case, monkeypatch, tmp_path, drift):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        _, final, jobs, _, provider = _retired(case, source, options, state)
        done = service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final)

    with db.bind(db.configure(state.uri)):
        jobs = SqlAlchemyJobRepository()
        assert _db_lease_lookup(source.engagement_id) is None
        retired = jobs.get(retirement._child_id(source.core_job_id))
        if drift == "legacy-source-free-digest":
            original = service._historical_parent(done)
            old_digest = _fingerprint({
                "jobs": [asdict(row) for row in (
                    original, jobs.get(source.core_job_id),
                    jobs.get(service.initial_parent_id(source.core_job_id)),
                    jobs.get(service.preview_child_id(source.core_job_id)),
                    jobs.get(service.apply_child_id(source.core_job_id)))],
                "plan": asdict(final["plan_repository"].get(source.core_plan_id)),
            })
            assert old_digest != retired.input["historicalAuthoritySha256"]
            jobs.save(replace(retired, input={**retired.input,
                "historicalAuthoritySha256": old_digest}))
        else:
            altered_source = dict(done.input["source"])
            altered_source[drift] = (["foreign-host", "foreign-firewall"]
                                    if drift == "owned_inspector_record_ids" else "0" * 64)
            source_sha = _fingerprint(altered_source)
            changed = replace(done, input={**done.input, "source": altered_source,
                                          "sourceSha256": source_sha})
            changed_retired = replace(retired, input={**retired.input, "sourceSha256": source_sha})
            jobs.save(changed_retired)
            jobs.save(replace(changed, events=[
                replace(done.events[0], data={"sourceSha256": source_sha}),
                service._terminal_event(changed, changed_retired)]))
        monkeypatch.setattr(service, "_authority", lambda *_a, **_k: pytest.fail("fence reopened"))
        monkeypatch.setattr(service, "retire_mixed_zero_apply_inspector",
                            lambda *_a, **_k: pytest.fail("retirement replayed"))
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            service.recognize_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, environment="devtest",
                job_repository=jobs, plan_repository=final["plan_repository"],
                sketch_repository=final["sketch_repository"])
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)



def test_cleanup_metadata_receipt_allows_only_exact_versioned_projection(
        case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(case, monkeypatch, tmp_path)
    with db.bind(state):
        _, final, jobs, resources, provider = _retired(case, source, options, state)
        done = service.finish_mixed_zero_apply_terminal(
            source.engagement_id, source.core_job_id, **final)

    with db.bind(db.configure(state.uri)):
        jobs = SqlAlchemyJobRepository()
        resources = service.SqlAlchemyProviderResourceRepository()
        retired = jobs.get(retirement._child_id(source.core_job_id))

        def recognize():
            return service.recognize_mixed_zero_apply_terminal(
                source.engagement_id, source.core_job_id, environment="devtest",
                job_repository=jobs, plan_repository=final["plan_repository"],
                sketch_repository=final["sketch_repository"])

        assert recognize() == done
        for version in (None, True, 0, 2, "1"):
            jobs.save(replace(retired, input={**retired.input, "cleanupMetadataVersion": version}))
            with pytest.raises(service.MixedZeroApplyTerminalAttention):
                recognize()
        jobs.save(retired)
        host = next(row for row in resources.list_for_engagement(source.engagement_id)
                    if row.resource_type == "inspector_instance")
        def save_literal(row):
            resources.save(row)
            # ORM JSON equality treats 0 and False alike; persist the malformed
            # literal explicitly so the guard really sees the wrong type.
            db.session.query(ProviderResourceRecordModel).filter_by(id=row.id).update(
                {"metadata_json": row.metadata})
            db.session.commit()

        for changed in (
            replace(host, metadata={**host.metadata, "cleanupRequired": True}),
            replace(host, metadata={**host.metadata, "cleanupRequired": 0}),
            replace(host, metadata={**host.metadata, "unreviewed": "changed"}),
            replace(host, adoption_job_id="job-other-owner"),
            replace(host, resource_type="unrelated-resource"),
            replace(host, status="active"),
            replace(host, lifecycle_state="running"),
            replace(host, destroyed_at=None),
        ):
            save_literal(changed)
            with pytest.raises(service.MixedZeroApplyTerminalAttention):
                recognize()
            save_literal(host)

        # Simulate the exact pre-version receipt/rows: no cleanup projection.
        legacy_input = dict(retired.input)
        legacy_input.pop("cleanupMetadataVersion")
        jobs.save(replace(retired, input=legacy_input))
        for row in resources.list_for_engagement(source.engagement_id):
            original = retired.input["hostRecord" if row.resource_type == "inspector_instance"
                                     else "firewallRecord"]
            resources.save(replace(row, metadata=original["metadata"]))
        assert recognize() == done
        old_host = next(row for row in resources.list_for_engagement(source.engagement_id)
                        if row.resource_type == "inspector_instance")
        resources.save(replace(old_host, metadata={**old_host.metadata, "unreviewed": "changed"}))
        with pytest.raises(service.MixedZeroApplyTerminalAttention):
            recognize()
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)
