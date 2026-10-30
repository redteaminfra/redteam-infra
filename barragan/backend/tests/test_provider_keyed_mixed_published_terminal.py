# Copyright (c) 2026, Oracle and/or its affiliates.
"""Offline published terminal receipt and owned-row identity checks."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_published_terminal as terminal
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.provider_resource_repository import StoredProviderResourceRecord
from app.storage.sketch_chain_repository import StoredSketchChain


def _job(identifier, action, status="succeeded", *, inputs=None, events=None):
    return StoredJobRun(identifier, action, status, "engagement:eng-a", "engagement",
                        "eng-a", "operator", inputs or {}, [],
                        "2026-10-19T00:00:00+00:00",
                        None if status == "queued" else "2026-10-19T00:00:01+00:00",
                        None if status == "queued" else "2026-10-19T00:00:02+00:00",
                        events or [])


def _chain(chain_id):
    return StoredSketchChain(chain_id, "eng-a", "proxy01", "linode", "us-sea",
                             "small", "digitalocean", "nyc3", "small", "deployed",
                             False, "", "job-deploy", "", "/tmp/workspace",
                             [{"providerInstanceId": "101"}],
                             "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:01+00:00")


def _record(identifier, provider, resource_id, *, status="active", source="barragan",
            resource_type="droplet", terraform_address=None):
    return StoredProviderResourceRecord(identifier, "eng-a", "eng", provider,
        resource_type, resource_id, identifier, "nyc3", status, status, source,
        {"barraganOwned": source == "barragan",
         **({"terraformAddress": terraform_address} if terraform_address else {})}, "job-deploy",
        "2026-10-19T00:00:00+00:00", "2026-10-19T00:00:01+00:00",
        "2026-10-19T00:00:02+00:00" if status == "destroyed" else None)


def case(monkeypatch):
    parent = _job(terminal.parent_id("job-core"), terminal.ACTION, "queued",
                  inputs={"reviewScope": {"ownedInspectorRecordIds": ["host", "firewall"]},
                          "engagementName": "eng", "publishedSourceSha256": "a" * 64,
                          "planSetSha256": "b" * 64})
    initial = _job("job-initial", "initial")
    core = _job("job-core", "core")
    plan = SimpleNamespace(id="plan-core")
    source = SimpleNamespace(parent_job_id=initial.id, core_plan_id=plan.id,
                             chain_ids=("chain-l", "chain-d"),
                             ordered_providers=("linode", "digitalocean"))
    scopes = ({"provider": "linode", "resources": [
                  {"address": "linode_instance.middle[\"us-sea\"]", "id": "201",
                   "kind": "instance"}]},
              {"provider": "digitalocean", "resources": [
                  {"address": "digitalocean_droplet.edge[\"nyc3\"]", "id": "101",
                   "kind": "droplet"}]})
    review = SimpleNamespace(source=source, provider_scopes=scopes)
    sealed = SimpleNamespace(plan_set_sha256="b" * 64)
    first = _job(terminal.child_id(core.id, "linode"),
                 "provider_keyed_mixed_published_destroy_apply",
                 events=[JobEvent(n, "info", f"event-{n}", {}) for n in range(1, 8)] +
                        [JobEvent(8, "info", "absent", {"receiptSha256": "c" * 64})])
    second = _job(terminal.child_id(core.id, "digitalocean"),
                  "provider_keyed_mixed_published_destroy_apply",
                  inputs={"priorAbsenceReceiptSha256": "c" * 64},
                  events=[JobEvent(n, "info", f"event-{n}", {}) for n in range(1, 8)] +
                         [JobEvent(8, "info", "absent", {"receiptSha256": "d" * 64})])
    absent = _job("job-absent", terminal.OCI_ABSENCE_ACTION,
                  inputs={"teardownParentId": parent.id},
                  events=[JobEvent(n, "info", f"event-{n}", {}) for n in range(1, 4)])
    negative = _job("job-negative", terminal.NEGATIVE_ACTION,
                    inputs={"ociAbsenceJobId": absent.id,
                            "ociAbsenceJournalSha256": job_event_digest(absent.events)},
                    events=[JobEvent(n, "info", f"event-{n}", {}) for n in range(1, 4)])
    selector = _job(terminal.selector_id(core.id), terminal.SELECTOR_ACTION,
                    inputs={"teardownParentId": parent.id,
                            "inspectorNegativeJournalSha256": job_event_digest(negative.events),
                            "doAbsenceReceiptSha256": "d" * 64},
                    events=[JobEvent(1, "info", "selector", {})])
    retirement = _job(terminal.retirement_id(core.id), terminal.RETIRE_ACTION,
                      inputs={"teardownParentId": parent.id,
                              "negativeJournalSha256": job_event_digest(negative.events),
                              "historicalAuthoritySha256": "authority",
                              "hostId": "301", "firewallId": "302"})
    mapping = {job.id: job for job in (parent, initial, core, first, second,
                                       absent, negative, selector, retirement)}
    jobs = SimpleNamespace(get=mapping.get)
    plans = SimpleNamespace(get=lambda identifier: plan if identifier == plan.id else None)
    rows = [_chain("chain-l"), _chain("chain-d")]
    records = [_record("host", "linode", "301", status="destroyed"),
               _record("firewall", "linode", "302", status="destroyed"),
               _record("owned", "digitalocean", "101"),
               _record("unmanaged", "digitalocean", "999", source="provider_inventory")]
    resources = SimpleNamespace(list_for_engagement=lambda _: records)
    chains = SimpleNamespace(list_for_engagement=lambda _: rows)
    settings = SimpleNamespace(get=lambda _: SimpleNamespace(current_host={}))
    monkeypatch.setattr(terminal, "saved_published_mixed_initial_review", lambda _: review)
    monkeypatch.setattr(terminal, "saved_published_mixed_destroy_plans", lambda _: sealed)
    monkeypatch.setattr(terminal, "recognize_published_mixed_plans_sealed", lambda *args: parent)
    monkeypatch.setattr(terminal, "recognize_published_mixed_destroy_child", lambda *args: "absence_proved")
    monkeypatch.setattr(terminal, "_authority", lambda *args, **kwargs:
                        (parent, core, initial, None, None, plan, None,
                         SimpleNamespace(resources=())))
    monkeypatch.setattr(terminal, "_authority_digest", lambda _: "authority")
    monkeypatch.setattr(terminal, "_saved_public_receipts", lambda *args: None)
    monkeypatch.setattr(terminal, "_saved_selector", lambda *args: None)
    monkeypatch.setattr(terminal, "latest_negative_attempt", lambda *args: negative)
    monkeypatch.setattr(terminal, "retirement_messages", lambda *args:
                        ["mixed Inspector local retirement committed"])
    lookup = lambda _: (plan.id, terminal._FENCE)
    return jobs, plans, settings, resources, chains, lookup, mapping, records


def test_history_retires_only_exact_owned_reviewed_record(monkeypatch):
    args = case(monkeypatch)
    ghost = replace(_chain("old-aborted"), status="aborted", burned=False,
                    deploy_job_id="", teardown_job_id="",
                    terraform_working_directory="", nodes=[])
    original_rows = args[4].list_for_engagement("eng-a")
    original_rows.append(ghost)
    parent, plan, rows, retire, evidence = terminal._history(
        "eng-a", "job-core", *args[:6])
    assert original_rows[-1] == ghost
    assert parent.id == terminal.parent_id("job-core")
    assert [row.id for row in retire] == ["owned"]
    assert {row.chain_id for row in rows} == {"chain-l", "chain-d"}
    assert len(evidence["providerJournalSha256"]) == 2
    event = terminal._terminal_event(parent, evidence)
    assert event.data["finalCleanupStatus"] == "verified_clean"
    assert event.data["terminalEvidenceSha256"] == terminal._fingerprint(evidence)


def test_crossed_provider_absence_handoff_is_rejected(monkeypatch):
    args = case(monkeypatch)
    mapping = args[6]
    second_id = terminal.child_id("job-core", "digitalocean")
    mapping[second_id] = replace(mapping[second_id], input={"priorAbsenceReceiptSha256": "0" * 64})
    with pytest.raises(ValueError, match="handoff"):
        terminal._history("eng-a", "job-core", *args[:6])


def test_unreviewed_owned_record_is_rejected_without_retiring_unmanaged(monkeypatch):
    args = case(monkeypatch)
    args[7].append(_record("alien-owned", "digitalocean", "999"))
    with pytest.raises(ValueError, match="unrecognized active owned"):
        terminal._history("eng-a", "job-core", *args[:6])


def test_same_numeric_id_on_different_linode_resource_type_is_not_owned_scope(monkeypatch):
    args = case(monkeypatch)
    # The reviewed Linode instance has ID 201. Its firewall can independently
    # receive that same numeric ID, but is not in this reviewed scope.
    args[7].append(_record("colliding-firewall", "linode", "201",
                           resource_type="linode_firewall"))
    with pytest.raises(ValueError, match="unrecognized active owned"):
        terminal._history("eng-a", "job-core", *args[:6])


def test_record_address_metadata_must_match_reviewed_address(monkeypatch):
    args = case(monkeypatch)
    args[7][2] = replace(args[7][2], metadata={
        "barraganOwned": True, "terraformAddress": 'digitalocean_droplet.edge["other"]'})
    with pytest.raises(ValueError, match="unrecognized active owned"):
        terminal._history("eng-a", "job-core", *args[:6])


def test_saved_selector_requires_exact_terminal_event(monkeypatch):
    check = terminal._saved_selector
    jobs, plans, *_rest = case(monkeypatch)
    parent = jobs.get(terminal.parent_id("job-core"))
    review = SimpleNamespace(source=SimpleNamespace(core_job_id="job-core"))
    sealed = SimpleNamespace(plan_set_sha256="b" * 64)
    absent = jobs.get("job-absent")
    negative = jobs.get("job-negative")
    base = {
        "selectorTag": "s123", "reviewSha256": "a" * 64,
        "planSetSha256": "b" * 64, "doAbsenceReceiptSha256": "d" * 64,
        "ociAbsenceJobId": absent.id,
        "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "inspectorNegativeJobId": negative.id,
        "inspectorNegativeJournalSha256": job_event_digest(negative.events),
    }
    prefix = [
        JobEvent(1, "info", "mixed published selector retirement queued", {}),
        JobEvent(2, "info", "mixed published selector retirement started", {}),
    ]
    valid = replace(jobs.get(terminal.selector_id("job-core")), input=base,
                    events=prefix + [JobEvent(3, "info",
                        "mixed published selector already absent",
                        {"selectorTag": "s123", "exactGetStatus": 404})])
    check(parent, review, sealed, valid, absent, negative, "d" * 64)
    bad = replace(valid, events=prefix + [JobEvent(3, "info",
        "mixed published selector already absent",
        {"selectorTag": "s123", "exactGetStatus": 200})])
    with pytest.raises(ValueError, match="terminal journal"):
        check(parent, review, sealed, bad, absent, negative, "d" * 64)


def test_saved_public_receipts_reject_crossed_oci_absence(monkeypatch):
    check = terminal._saved_public_receipts
    jobs, _, *_ = case(monkeypatch)
    parent = replace(jobs.get(terminal.parent_id("job-core")),
                     input={**jobs.get(terminal.parent_id("job-core")).input,
                            "publishedSourceSha256": "a" * 64})
    core = jobs.get("job-core")
    plan = SimpleNamespace(id="plan-core", evidence={"proxyCount": 1})
    preview = _job("job-preview", "preview")
    applied = _job("job-applied", "apply")
    absent = _job("job-absent", terminal.OCI_ABSENCE_ACTION,
                  inputs={"teardownParentId": parent.id, "coreJobId": core.id,
                          "corePlanId": plan.id, "sourceSha256": "a" * 64,
                          "previewJobId": preview.id,
                          "previewJournalSha256": job_event_digest(preview.events),
                          "applyJobId": applied.id,
                          "applyJournalSha256": job_event_digest(applied.events)},
                  events=[JobEvent(1, "info", "mixed core absence queued", {}),
                          JobEvent(2, "info", "mixed core absence started", {}),
                          JobEvent(3, "info", "mixed core exact absence proved",
                                   {"ociAbsenceWitness": {"phase": "absent"}})])
    negative = _job("job-negative", terminal.NEGATIVE_ACTION,
                    inputs={"teardownParentId": parent.id, "coreJobId": core.id,
                            "corePlanId": plan.id, "sourceSha256": "a" * 64,
                            "ociAbsenceJobId": absent.id,
                            "ociAbsenceJournalSha256": job_event_digest(absent.events),
                            "positiveControl": {"control": True}},
                    events=[JobEvent(1, "info", "mixed Inspector negative queued", {}),
                            JobEvent(2, "info", "mixed Inspector negative started", {}),
                            JobEvent(3, "info", "mixed Inspector exact public negative proved",
                                     {"rounds": [1, 2], "classifications": [True, True],
                                      "targetSha256": terminal._fingerprint([])})])
    monkeypatch.setattr(terminal, "core_targets", lambda *_: [])
    monkeypatch.setattr(terminal, "_classified_results", lambda *args: True)
    check(parent, core, plan, preview, applied, absent, negative)
    crossed = replace(negative, input={**negative.input,
                                       "ociAbsenceJournalSha256": "0" * 64})
    with pytest.raises(ValueError, match="public-negative journal"):
        check(parent, core, plan, preview, applied, absent, crossed)


def test_non_devtest_terminal_fails_before_mutation():
    with pytest.raises(terminal.PublishedMixedTerminalAttention,
                       match="DevTest-only"):
        terminal.finish_published_mixed_terminal("eng-a", "job-core",
                                                 environment="prod")


def test_persisted_terminal_transaction_preserves_desired_topology_and_restarts(
        monkeypatch, tmp_path):
    from app.storage.database import db
    from app.storage.job_repository import SqlAlchemyJobRepository
    from app.storage.provider_resource_repository import SqlAlchemyProviderResourceRepository
    from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
    from app.storage.models import (
        CoreMutationLeaseModel, EngagementLifecycleEventModel,
        EngagementLifecycleModel, EngagementModel,
    )

    state = db.configure(f"sqlite:///{tmp_path / 'published-terminal.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id="eng-a", name="eng", status="active", owner="operator",
            template_id="small-dev", input_parameters={"kept": "for-redeploy"},
            sketch_state_schema="provider-keyed-v2"))
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-a", owner_id="plan-core",
            operation=terminal._FENCE))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        resources = SqlAlchemyProviderResourceRepository()
        chains = SqlAlchemySketchChainRepository()
        parent = _job(terminal.parent_id("job-core"), terminal.ACTION, "queued",
                      inputs={"phase": "plans_sealed", "planSetSha256": "b" * 64,
                              "publishedSourceSha256": "a" * 64,
                              "publishedSource": {"chain_ids": ["chain-l", "chain-d"]}},
                      events=[JobEvent(1, "info", "queued", {}),
                              JobEvent(2, "info", "sealed", {})])
        parent = jobs.save(parent)
        for chain_id in ("chain-l", "chain-d"):
            chains.save(replace(_chain(chain_id), edge_count=2,
                                edge_intents=[{"region": "nyc3", "count": 2}]))
        resources.save(_record("owned", "digitalocean", "101"))
        resources.save(_record("unmanaged", "digitalocean", "999",
                               source="provider_inventory"))
        # The preceding read-only receipt gates are tested independently. This
        # fixture exercises their local final writer using persisted rows.
        def authenticated_history(*_args):
            current = jobs.get(parent.id)
            current_rows = chains.list_for_engagement("eng-a")
            current_records = resources.list_for_engagement("eng-a")
            lease = db.session.query(CoreMutationLeaseModel).filter_by(
                engagement_id="eng-a").one_or_none()
            if (current != parent or lease is None
                    or lease.owner_id != "plan-core"
                    or len(current_rows) != 2
                    or any(row.status != "deployed" for row in current_rows)):
                raise ValueError("authenticated terminal source changed")
            owned = [row for row in current_records if row.id == "owned"]
            if len(owned) != 1 or owned[0].status != "active":
                raise ValueError("owned receipt changed")
            evidence = {
                "providerJournalSha256": ["c" * 64, "d" * 64],
                "ociAbsenceJournalSha256": "e" * 64,
                "inspectorJournalSha256": "f" * 64,
                "rows": [row.to_dict() for row in current_rows],
                "owned": [row.to_dict() for row in owned],
            }
            return current, SimpleNamespace(id="plan-core"), current_rows, owned, evidence
        monkeypatch.setattr(terminal, "_history", authenticated_history)
        real_resolution = terminal.resolve_engagement_lifecycle
        monkeypatch.setattr(terminal, "resolve_engagement_lifecycle",
                            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                                ValueError("late lifecycle drift")))
        with pytest.raises(terminal.PublishedMixedTerminalAttention):
            terminal.finish_published_mixed_terminal(
                "eng-a", "job-core", environment="devtest",
                job_repository=jobs, provider_resource_repository=resources,
                sketch_repository=chains)
        assert jobs.get(parent.id).status == "queued"
        assert all(row.status == "deployed" for row in chains.list_for_engagement("eng-a"))
        assert resources.get("owned").status == "active"
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id="eng-a").count() == 1
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id="eng-a").count() == 0
        monkeypatch.setattr(terminal, "resolve_engagement_lifecycle", real_resolution)
        result = terminal.finish_published_mixed_terminal(
            "eng-a", "job-core", environment="devtest",
            job_repository=jobs, provider_resource_repository=resources,
            sketch_repository=chains, lease_lookup=lambda engagement_id:
                (("plan-core", terminal._FENCE) if db.session.query(
                    CoreMutationLeaseModel).filter_by(
                        engagement_id=engagement_id).one_or_none() else None))
        assert result.status == "succeeded"
        assert result.input["phase"] == terminal._PHASE
        assert result.events[-1].data["finalCleanupStatus"] == "verified_clean"
        for row in chains.list_for_engagement("eng-a"):
            assert row.status == "destroyed" and row.nodes == []
            assert row.teardown_job_id == parent.id
            assert row.edge_count == 2
            assert row.edge_intents == [{"region": "nyc3", "count": 2}]
            assert row.assigned_proxy == "proxy01"
            assert row.deploy_job_id == "job-deploy"
        assert resources.get("owned").status == "destroyed"
        assert resources.get("owned").destroyed_at is not None
        assert resources.get("unmanaged").status == "active"
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id="eng-a").count() == 0
        assert db.session.query(EngagementLifecycleModel).filter_by(
            engagement_id="eng-a").one().state == "destroyed"
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id="eng-a").count() == 1
        assert db.session.get(EngagementModel, "eng-a").input_parameters == {
            "kept": "for-redeploy"}
        restarted = terminal.finish_published_mixed_terminal(
            "eng-a", "job-core", environment="devtest",
            job_repository=jobs, provider_resource_repository=resources,
            sketch_repository=chains, lease_lookup=lambda _: None)
        assert restarted == result
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id="eng-a").count() == 1
