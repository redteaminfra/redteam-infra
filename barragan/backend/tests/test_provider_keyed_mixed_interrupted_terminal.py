# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact private interrupted terminal receipts; no provider mutation."""

from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_interrupted_terminal as service
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_interrupted_oci_tail import InterruptedHistoricalOciSource
from app.services.provider_keyed_mixed_interrupted_cleanup import (
    _canonical, propose_mixed_interrupted_cleanup,
)
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.database import db
from app.storage.models import CoreMutationLeaseModel, EngagementLifecycleEventModel
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_cleanup import _boundary
from test_provider_keyed_mixed_zero_apply_inspector_retirement import (
    _recovered_show_applied, _sql_ready, case as zero_case,
)
from test_provider_keyed_mixed_zero_apply_terminal import _retired
from test_provider_keyed_mixed_interrupted_oci_tail import (
    _interrupted_go_case, case as oci_case,
)
from app.services import provider_keyed_mixed_zero_apply_core_apply as apply_service


def _sealed(ready):
    initial, review, plans = _boundary(ready)
    parent = propose_mixed_interrupted_cleanup(initial, review, requested_by="operator")
    parent = replace(parent, input={**parent.input, "phase": "plans_sealed"},
                     events=parent.events + [JobEvent(
                         2, "info", "both mixed destroy plans sealed",
                         {"planSet": _canonical(plans.__dict__ | {
                             "plans": [plan.__dict__ for plan in plans.plans]}),
                          "planSetSha256": plans.plan_set_sha256})])
    return initial, review, plans, parent


def test_provider_history_authenticates_both_unstarted_orders(ready):
    initial, review, plans, parent = _sealed(ready)
    jobs = SimpleNamespace(get=lambda _job_id: None)
    assert service._provider_history(initial, parent, review, plans, jobs) == (
        "none", "none")
    forged = replace(review, scopes=(replace(review.scopes[0],
                       child_journal_sha256="0" * 64), review.scopes[1]))
    with pytest.raises(ValueError, match="journal changed"):
        service._provider_history(initial, parent, forged, plans, jobs)


def test_selector_terminal_requires_exact_seal_and_four_event_receipt(ready):
    initial, review, plans, parent = _sealed(ready)
    do_scope = next(row for row in review.scopes if row.provider == "digitalocean")
    assert service._selector_terminal(None, initial, parent, review, plans,
                                      None, None) is None
    with pytest.raises(ValueError, match="unexpected selector"):
        service._selector_terminal(SimpleNamespace(), initial, parent, review,
                                   plans, None, None)
    pending_review = replace(review, scopes=tuple(replace(
        row, selector_retirement_pending=True) if row.provider == "digitalocean"
        else row for row in review.scopes))
    pending_scope = next(row for row in pending_review.scopes
                         if row.provider == "digitalocean")
    absent = SimpleNamespace(id="job-absent", events=[JobEvent(1, "info", "absent", {})])
    negative = SimpleNamespace(id="job-negative", events=[JobEvent(1, "info", "negative", {})])
    policy = initial.events[5].data["reviewedPolicy"]["digitalocean"]
    base = {
        "schema": "mixed-interrupted-selector-retirement-v1",
        "engagementId": parent.target_id,
        "coreJobId": review.core_job_id,
        "corePlanId": parent.input["corePlanId"],
        "teardownParentId": parent.id,
        "reviewSha256": review.review_sha256,
        "planSetSha256": plans.plan_set_sha256,
        "doScopeSha256": service._scope_sha(pending_scope),
        "selectorTag": do_scope.selector_tag,
        "providerConnectionId": policy["provider_connection_id"],
        "credentialSecretSha256": policy["credential_secret_sha256"],
        "credentialUpdatedAt": policy["credential_updated_at"],
        "ociAbsenceJobId": absent.id,
        "ociAbsenceJournalSha256": job_event_digest(absent.events),
        "inspectorNegativeJobId": negative.id,
        "inspectorNegativeJournalSha256": job_event_digest(negative.events),
        "mutation": True,
    }
    intent = {"selectorTag": do_scope.selector_tag,
              "doScopeSha256": base["doScopeSha256"],
              "ociAbsenceJournalSha256": base["ociAbsenceJournalSha256"],
              "inspectorNegativeJournalSha256": base["inspectorNegativeJournalSha256"]}
    events = [
        JobEvent(1, "info", "mixed interrupted selector retirement queued", {}),
        JobEvent(2, "info", "mixed interrupted selector retirement started", {}),
        JobEvent(3, "info", "mixed interrupted selector DELETE intended", intent),
        JobEvent(4, "info", "mixed interrupted selector absence reconciled", {
            "selectorTag": do_scope.selector_tag, "exactGetStatus": 404,
            "completeTagListAbsent": True}),
    ]
    selector = StoredJobRun(
        service.selector_id(review.core_job_id), service.SELECTOR_ACTION,
        "succeeded", parent.target, parent.target_type, parent.target_id,
        parent.requested_by, base, [], parent.created_at, parent.created_at,
        parent.created_at, events)
    assert service._selector_terminal(selector, initial, parent, pending_review,
                                      plans, absent, negative) == selector
    with pytest.raises(ValueError, match="receipt differs"):
        service._selector_terminal(replace(selector, events=events[:-1] + [
            JobEvent(4, "info", "mixed interrupted selector absence reconciled", {
                "selectorTag": do_scope.selector_tag, "exactGetStatus": 200,
                "completeTagListAbsent": False})]), initial, parent,
            pending_review, plans, absent, negative)


@pytest.mark.parametrize("recovered_show", [False, True])
def test_oci_go_saves_exact_two_provider_absence_for_terminal(
        oci_case, monkeypatch, recovered_show):
    source, _, options, captured = _interrupted_go_case(oci_case, monkeypatch)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id,
        **{**options, "interrupted": True})
    if recovered_show:
        applied = _recovered_show_applied(applied)
    parent = captured["parent"]
    review, plans = service._saved_review(parent), service._saved_plans(parent)
    digest = service._saved_sketch_absence(parent, review, plans, applied,
                                           ("none", "none"))
    assert digest == captured["authority"].post_sketch_absence.checkpoint_sha256
    assert service._terminal_event(parent, ("none", "none"), applied,
                                   SimpleNamespace(id="absent", events=[]),
                                   SimpleNamespace(id="negative", events=[]), None,
                                   SimpleNamespace(id="retired", events=[])).data[
                                       "postSketchAbsenceSha256"] == digest
    go_index = 11 if recovered_show else 8
    event = applied.events[go_index]
    missing = replace(applied, events=applied.events[:go_index] + [replace(
        event, data={key: value for key, value in event.data.items()
                     if key != "postSketchAbsence"})] + applied.events[go_index + 1:])
    with pytest.raises(ValueError, match="checkpoint differs"):
        service._saved_sketch_absence(parent, review, plans, missing,
                                      ("none", "none"))
    changed = dict(event.data["postSketchAbsence"])
    receipts = [dict(row) for row in changed["receipts"]]
    receipts[0]["verified_absent_ids"] = ["999999"]
    changed["receipts"] = receipts
    drift = replace(applied, events=applied.events[:go_index] + [replace(
        event, data={**event.data, "postSketchAbsence": changed})]
        + applied.events[go_index + 1:])
    with pytest.raises(ValueError, match="ownership differs"):
        service._saved_sketch_absence(parent, review, plans, drift,
                                      ("none", "none"))
    if recovered_show:
        forged = list(applied.events)
        forged[4] = replace(forged[4], data={
            **forged[4].data, "originalJournalSha256": "0" * 64})
        with pytest.raises(ValueError, match="recovery marker differs"):
            service._saved_sketch_absence(parent, review, plans,
                                          replace(applied, events=forged),
                                          ("none", "none"))


def test_terminal_commit_and_late_residue_rollback_use_one_sql_writer_slot(
        zero_case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(zero_case, monkeypatch, tmp_path)
    with db.bind(state):
        _, final, jobs, resources, provider = _retired(
            zero_case, source, options, state)
        old_parent = jobs.get(
            f"job-provider-keyed-mixed-zero-apply-cleanup-"
            f"{source.core_job_id.removeprefix('job-')}")
        parent = replace(old_parent, id=service._parent_id(source.core_job_id),
                         action=service.ACTION,
                         input={"phase": "plans_sealed", "sourceSha256": "a" * 64,
                                "corePlanId": source.core_plan_id},
                         events=[JobEvent(1, "info", "fenced", {}),
                                 JobEvent(2, "info", "sealed", {
                                     "planSetSha256": "b" * 64})])
        initial = jobs.get(service.initial_id(source.core_job_id))
        review, plans = SimpleNamespace(), SimpleNamespace()
        jobs.save(parent)
        core = jobs.get(source.core_job_id)
        preview = jobs.get(service.oci_preview_id(source.core_job_id))
        applied = jobs.get(service.oci_apply_id(source.core_job_id))
        plan = final["plan_repository"].get(source.core_plan_id)
        absent = next(row for row in jobs.list_for_engagement(source.engagement_id)
                      if row.action == service.OCI_ABSENCE_ACTION)
        negative = jobs.get(service.negative_id(source.core_job_id))
        retirement = jobs.get(service.retirement_id(source.core_job_id))
        service._saved_public_receipts(old_parent, core, plan, preview, applied,
                                       absent, negative)
        altered_negative = replace(negative, events=negative.events[:-1] + [
            JobEvent(3, "info", "mixed Inspector exact public negative proved", {
                **negative.events[-1].data, "classifications": []})])
        with pytest.raises(ValueError, match="historical public negative"):
            service._saved_public_receipts(old_parent, core, plan, preview,
                                           applied, absent, altered_negative)
        historical_source = InterruptedHistoricalOciSource(
            preview.input["stateSha256"], preview.input["inventorySha256"],
            tuple(source.owned_inspector_record_ids))
        historical = (parent, core, initial, preview, applied, plan, historical_source)
        receipts = (historical, review, plans, ("none", "none"), absent,
                    negative, None, retirement)
        monkeypatch.setattr(service, "_receipts", lambda *_a, **_k: receipts)
        monkeypatch.setattr(service, "_authority", lambda *_a, **_k: historical)
        monkeypatch.setattr(service, "_provider_history", lambda *_a, **_k:
                            ("none", "none"))
        monkeypatch.setattr(service, "retire_mixed_zero_apply_inspector",
                            lambda *_a, **_k: retirement)
        monkeypatch.setattr(service, "recognize_mixed_interrupted_terminal",
                            lambda *_a, **_k: jobs.get(parent.id))
        monkeypatch.setattr(service, "resolve_engagement_lifecycle",
                            lambda *_a, **_k: SimpleNamespace(
                                state="destroyed", evidence=[{
                                    "kind": "engagement_teardown_job", "id": parent.id,
                                    "status": "succeeded"}]))
        original_residue = service._residue
        monkeypatch.setattr(service, "_residue",
                            lambda *_a, **_k: (_ for _ in ()).throw(
                                ValueError("late owned residue")))
        with pytest.raises(service.MixedInterruptedTerminalAttention):
            service.finish_mixed_interrupted_terminal(
                source.engagement_id, source.core_job_id, **final)
        assert jobs.get(parent.id).status == "queued"
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=source.engagement_id).count() == 1
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=source.engagement_id).count() == 0
        monkeypatch.setattr(service, "_residue", original_residue)
        completed = service.finish_mixed_interrupted_terminal(
            source.engagement_id, source.core_job_id, **final)
        assert completed.status == "succeeded"
        assert completed.events[-1].message == "mixed interrupted teardown complete"
        assert db.session.query(CoreMutationLeaseModel).filter_by(
            engagement_id=source.engagement_id).count() == 0
        assert db.session.query(EngagementLifecycleEventModel).filter_by(
            engagement_id=source.engagement_id).count() == 1
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)


def test_persisted_public_receipts_keep_source_and_review_seals_distinct(
        zero_case, monkeypatch, tmp_path):
    source, options, state = _sql_ready(zero_case, monkeypatch, tmp_path)
    with db.bind(state):
        _, final, jobs, _, _ = _retired(zero_case, source, options, state)
        zero_parent = jobs.get(
            "job-provider-keyed-mixed-zero-apply-cleanup-"
            + source.core_job_id.removeprefix("job-"))
        parent_id = service._parent_id(source.core_job_id)
        source_sha = _fingerprint(zero_parent.input["source"])
        review_sha = "a" * 64 if source_sha != "a" * 64 else "b" * 64
        jobs.save(replace(
            zero_parent, id=parent_id, action=service.ACTION,
            input={**zero_parent.input, "phase": "plans_sealed",
                   "sourceSha256": review_sha}))
        negative = jobs.get(service.negative_id(source.core_job_id))
        jobs.save(replace(negative, input={
            **negative.input, "teardownParentId": parent_id,
            "sourceSha256": review_sha}))
        core = jobs.get(source.core_job_id)
        plan = final["plan_repository"].get(source.core_plan_id)
        preview = jobs.get(service.oci_preview_id(source.core_job_id))
        applied = jobs.get(service.oci_apply_id(source.core_job_id))
        absent = next(row for row in jobs.list_for_engagement(source.engagement_id)
                      if row.action == service.OCI_ABSENCE_ACTION)
        jobs.save(replace(absent, input={
            **absent.input, "teardownParentId": parent_id}))
        absent = jobs.get(absent.id)
        saved_parent = jobs.get(parent_id)
        saved_negative = jobs.get(negative.id)
        assert source_sha != review_sha
        assert absent.input["sourceSha256"] == source_sha
        assert saved_negative.input["sourceSha256"] == review_sha
        service._saved_public_receipts(saved_parent, core, plan, preview,
                                       applied, absent, saved_negative)

        jobs.save(replace(absent, input={**absent.input, "sourceSha256": review_sha}))
        with pytest.raises(ValueError, match="historical OCI absence differs"):
            service._saved_public_receipts(saved_parent, core, plan, preview,
                                           applied, jobs.get(absent.id), saved_negative)
        jobs.save(absent)
        jobs.save(replace(saved_negative, input={
            **saved_negative.input, "sourceSha256": source_sha}))
        with pytest.raises(ValueError, match="historical public negative differs"):
            service._saved_public_receipts(saved_parent, core, plan, preview,
                                           applied, jobs.get(absent.id),
                                           jobs.get(saved_negative.id))


def _real_interrupted_terminal(zero_case, monkeypatch, tmp_path):
    """Reuse offline transport fixtures, routing every real service to interrupted mode."""
    import test_provider_keyed_mixed_zero_apply_core_absence as absence_fixture
    from app.services import provider_keyed_mixed_zero_apply_core_absence as absence
    from app.services import provider_keyed_mixed_zero_apply_inspector_negative as negative
    from app.services import provider_keyed_mixed_zero_apply_inspector_retirement as retirement
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
    from test_provider_keyed_mixed_zero_apply_inspector_retirement import Provider, _enter_sql

    def interrupted_go(case, patches):
        source, actions, options, _ = _interrupted_go_case(case, patches)
        return source, actions, None, {**options, "interrupted": True}

    original_absence = absence.prove_mixed_zero_apply_oci_core_absence
    original_negative = negative.prove_mixed_zero_apply_inspector_negative
    monkeypatch.setattr(absence_fixture, "_go_case", interrupted_go)
    monkeypatch.setattr(absence, "prove_mixed_zero_apply_oci_core_absence",
                        lambda *a, **kw: original_absence(*a, **{**kw, "interrupted": True}))
    monkeypatch.setattr(negative, "prove_mixed_zero_apply_inspector_negative",
                        lambda *a, **kw: original_negative(*a, **{**kw, "interrupted": True}))
    source, options, state = _sql_ready(zero_case, monkeypatch, tmp_path)
    # The reused core-preparation fixture creates zero-Apply scaffolding; the
    # interrupted engagement has only its own cleanup parent, never both.
    listed_jobs = zero_case.jobs.list_for_engagement
    monkeypatch.setattr(zero_case.jobs, "list_for_engagement", lambda *a, **kw: [
        row for row in listed_jobs(*a, **kw)
        if row.action != "provider_keyed_mixed_zero_apply_cleanup"])
    provider = Provider()
    with db.bind(state):
        kwargs, jobs, _, _ = _enter_sql(zero_case, source, options, state, provider)
        retired = retirement.retire_mixed_zero_apply_inspector(
            source.engagement_id, source.core_job_id, **kwargs, interrupted=True)
        assert retired.status == "succeeded"
        final = {key: kwargs[key] for key in (
            "environment", "state_root", "core_state_root", "job_repository",
            "plan_repository", "settings_repository", "provider_resource_repository")}
        final.update(sketch_repository=zero_case.args["sketch_repository"],
                     lease_lookup=_db_lease_lookup, identity_reader=lambda: {})
        completed = service.finish_mixed_interrupted_terminal(
            source.engagement_id, source.core_job_id, **final)
    return source, state, final, completed, retired, provider


def test_real_interrupted_writer_digest_recognized_after_session_restart(
        zero_case, monkeypatch, tmp_path):
    from app.services.provider_keyed_runtime_preflight import _db_lease_lookup

    source, state, final, completed, retired, provider = _real_interrupted_terminal(
        zero_case, monkeypatch, tmp_path)
    with db.bind(db.configure(state.uri)):
        jobs = SqlAlchemyJobRepository()
        assert _db_lease_lookup(source.engagement_id) is None
        canonical_digest = service._authority_digest
        seen = []

        def actual_digest(authority):
            digest = canonical_digest(authority)
            seen.append(digest)
            assert type(authority[6]) is InterruptedHistoricalOciSource
            return digest

        monkeypatch.setattr(service, "_authority_digest", actual_digest)
        monkeypatch.setattr(service, "_authority", lambda *_a, **_kw: pytest.fail("fence reopened"))
        monkeypatch.setattr(service, "retire_mixed_zero_apply_inspector",
                            lambda *_a, **_kw: pytest.fail("retirement replayed"))
        assert service.recognize_mixed_interrupted_terminal(
            source.engagement_id, source.core_job_id, environment="devtest",
            job_repository=jobs, plan_repository=final["plan_repository"],
            sketch_repository=final["sketch_repository"]) == completed
        assert seen == [retired.input["historicalAuthoritySha256"]]
        preview = jobs.get(service.oci_preview_id(source.core_job_id))
        for key, value in (
            ("stateSha256", "0" * 64), ("inventorySha256", "1" * 64),
            ("inspectorRecordIds", ["foreign-host", "foreign-firewall"]),
            ("inspectorRecordIds", ["duplicate", "duplicate"]),
            ("inspectorRecordIds", [None, "firewall"]),
            ("stateSha256", None), ("inventorySha256", "not-a-digest"),
        ):
            jobs.save(replace(preview, input={**preview.input, key: value}))
            with pytest.raises(service.MixedInterruptedTerminalAttention):
                service.recognize_mixed_interrupted_terminal(
                    source.engagement_id, source.core_job_id, environment="devtest",
                    job_repository=jobs, plan_repository=final["plan_repository"],
                    sketch_repository=final["sketch_repository"])
            jobs.save(preview)

        # This is negative input only: the historical source-less schema must
        # never be accepted beside the actual source-bound writer receipt.
        original = service._historical_parent(completed)
        source_free = _fingerprint({
            "jobs": [asdict(row) for row in (
                original, jobs.get(source.core_job_id),
                jobs.get(service.initial_id(source.core_job_id)), preview,
                jobs.get(service.oci_apply_id(source.core_job_id)))],
            "plan": asdict(final["plan_repository"].get(source.core_plan_id)),
        })
        assert source_free != retired.input["historicalAuthoritySha256"]
        jobs.save(replace(retired, input={**retired.input,
                                         "historicalAuthoritySha256": source_free}))
        with pytest.raises(service.MixedInterruptedTerminalAttention):
            service.recognize_mixed_interrupted_terminal(
                source.engagement_id, source.core_job_id, environment="devtest",
                job_repository=jobs, plan_repository=final["plan_repository"],
                sketch_repository=final["sketch_repository"])
        jobs.save(retired)
        for version in (None, True, 0, 2):
            jobs.save(replace(retired, input={**retired.input, "cleanupMetadataVersion": version}))
            with pytest.raises(service.MixedInterruptedTerminalAttention):
                service.recognize_mixed_interrupted_terminal(
                    source.engagement_id, source.core_job_id, environment="devtest",
                    job_repository=jobs, plan_repository=final["plan_repository"],
                    sketch_repository=final["sketch_repository"])
        assert (provider.host_deletes, provider.firewall_deletes) == (1, 1)
