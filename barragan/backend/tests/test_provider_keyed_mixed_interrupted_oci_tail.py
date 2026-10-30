# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private interrupted OCI tail reuses the mixed core one-shot preview."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_zero_apply_core_preview as preview_service
from app.services import provider_keyed_mixed_zero_apply_core_apply as apply_service
from app.services import provider_keyed_mixed_zero_apply_core_absence as absence_service
from app.services.provider_keyed_mixed_zero_apply_teardown_source import MixedZeroApplySource
from app.services.provider_keyed_mixed_interrupted_cleanup import _parent_id as interrupted_id
from app.services.provider_keyed_mixed_interrupted_oci_tail import advance_mixed_interrupted_oci_core
from app.services.provider_keyed_mixed_initial_plan_parent import (
    MixedInitialPlanParentError, _validate_parent, seal_mixed_initial_apply,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_id
from app.services import provider_keyed_mixed_initial_apply_child as initial_apply
from app.services.provider_keyed_mixed_initial_coordinator import (
    HANDOFF_MESSAGE, HANDOFF_PHASE, _handoff_data,
    recognize_mixed_initial_host_proof_handoff,
)
from app.services.provider_keyed_mixed_interrupted_source import review_mixed_interrupted_source
from app.services.provider_keyed_mixed_interrupted_post_sketch_absence import (
    prove_mixed_interrupted_post_sketch_absence,
)
from app.storage.job_repository import StoredJobRun, job_event_digest
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import EngagementModel
from test_provider_keyed_mixed_zero_apply_core_preview import case, _ready
from test_provider_keyed_mixed_zero_apply_core_apply import _go_case
from test_provider_keyed_mixed_zero_apply_core_absence import _empty_state, _absent
from test_provider_keyed_mixed_interrupted_post_sketch_absence import _sealed
from test_provider_keyed_mixed_interrupted_source import _snapshot


def _interrupted(case, source, monkeypatch):
    initial = case.jobs.get(initial_id(source.core_job_id))
    order = tuple(initial.input["orderedProviders"])
    review = review_mixed_interrupted_source(
        initial, {provider: None for provider in order},
        {provider: _snapshot(provider) for provider in order},
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    parent, _plans = _sealed(initial, review)
    case.jobs.save(parent)
    absence = prove_mixed_interrupted_post_sketch_absence(
        initial, parent, review, _plans,
        {provider: None for provider in order},
        {provider: None for provider in order},
        {provider: _snapshot(provider) for provider in order},
        fence=lambda: "stable", process_quiescent=lambda identity: True)
    authority = SimpleNamespace(
        parent=parent, core_state_sha256=source.core_state_sha256,
        core_inventory_sha256=source.core_inventory_sha256,
        core_job_id=source.core_job_id, core_plan_id=source.core_plan_id,
        core_resource_ids=(), selector_retirement_pending=False,
        owned_inspector_record_ids=source.owned_inspector_record_ids,
        post_sketch_absence=absence)
    monkeypatch.setattr(preview_service, "audit_current_interrupted_oci_tail",
                        lambda *a, **k: authority)
    return parent, authority


def test_interrupted_preview_saves_exact_parent_and_inspector_source(case, monkeypatch):
    seal_mixed_initial_apply(**case.plan_args)
    source, _, _, calls, options = _ready(case, monkeypatch)
    parent, authority = _interrupted(case, source, monkeypatch)
    result = preview_service.preview_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert result.status == "succeeded" and calls == ["plan", "show"]
    assert result.input["teardownParentId"] == parent.id
    assert result.input["schema"] == "mixed-interrupted-core-preview-v1"
    assert result.input["parentJournalSha256"] == job_event_digest(parent.events)
    assert result.input["inspectorRecordIds"] == list(authority.owned_inspector_record_ids)
    assert result.events[-1].data["sourceSha256"] == parent.input["sourceSha256"]


def test_interrupted_preview_rejects_source_change_before_plan(case, monkeypatch):
    seal_mixed_initial_apply(**case.plan_args)
    source, _, _, calls, options = _ready(case, monkeypatch)
    parent, authority = _interrupted(case, source, monkeypatch)
    monkeypatch.setattr(preview_service, "audit_current_interrupted_oci_tail",
                        lambda *a, **k: SimpleNamespace(
                            **{**vars(authority), "core_state_sha256": "0" * 64}))
    with pytest.raises(preview_service.MixedZeroApplyCorePreviewAttention):
        preview_service.preview_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert calls == []


def test_interrupted_preview_allows_unrelated_provider_inventory_change(case, monkeypatch):
    seal_mixed_initial_apply(**case.plan_args)
    source, _, _, calls, options = _ready(case, monkeypatch)
    _, authority = _interrupted(case, source, monkeypatch)
    observations = iter("defabc" * 10)

    def fresh(*args, **kwargs):
        absence = SimpleNamespace(**{**vars(authority.post_sketch_absence),
                                     "checkpoint_sha256": next(observations) * 64})
        return SimpleNamespace(**{**vars(authority), "post_sketch_absence": absence})

    monkeypatch.setattr(preview_service, "audit_current_interrupted_oci_tail", fresh)
    result = preview_service.preview_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert result.status == "succeeded" and calls == ["plan", "show"]


def _interrupted_go_case(case, monkeypatch):
    seal_mixed_initial_apply(**case.plan_args)
    original_preview = preview_service.preview_mixed_zero_apply_oci_core_destroy
    captured = {}

    def interrupted_preview(engagement_id, core_job_id, **options):
        zero = case.jobs.get(
            f"job-provider-keyed-mixed-zero-apply-cleanup-{core_job_id.removeprefix('job-')}")
        source = MixedZeroApplySource(**zero.input["source"])
        parent, authority = _interrupted(case, source, monkeypatch)
        captured.update(parent=parent, authority=authority)
        return original_preview(engagement_id, core_job_id,
                                **{**options, "interrupted": True})

    monkeypatch.setattr(preview_service, "preview_mixed_zero_apply_oci_core_destroy",
                        interrupted_preview)
    source, actions, _, options = _go_case(case, monkeypatch)
    monkeypatch.setattr(apply_service, "audit_current_interrupted_oci_tail",
                        lambda *a, **k: captured["authority"])
    return source, actions, options, captured


def _persist_host_handoff(case, core_job_id):
    """Store both exact terminal Apply journals and the seven-event checkpoint."""
    parent = case.jobs.get(initial_id(core_job_id))
    order = parent.input["orderedProviders"]
    seal = parent.events[5].data
    children = {}
    for index, provider in enumerate(order):
        base = initial_apply._base(parent, seal, provider, index)
        plan_name = (initial_apply._LINODE_PLAN if provider == "linode"
                     else initial_apply._DO_PLAN)
        plan_path = f"/tmp/opaque-offline/{plan_name}"
        command = ["/usr/bin/terraform", "apply", "-input=false", "-lock=true",
                   "-no-color", plan_path]
        invocation = f"offline-{provider}"
        rows = [JobEvent(1, "info", "mixed provider Apply queued", {}),
                JobEvent(2, "info", "mixed provider Apply started", {})]
        if provider == "digitalocean":
            selector = seal["reviewedPolicy"][provider]["selector_tag"]
            rows += [
                JobEvent(3, "info", "mixed selector absent before Apply",
                         {"absenceSha256": "a" * 64, "selectorTag": selector}),
                JobEvent(4, "info", "mixed selector POST intended",
                         {"selectorTag": selector, "absenceSha256": "a" * 64}),
                JobEvent(5, "info", "mixed selector 201 received",
                         {"selectorTag": selector, "httpStatus": 201}),
                JobEvent(6, "info", "mixed selector exclusive visibility proved",
                         {"selectorTag": selector, "visibleSha256": "b" * 64}),
            ]
        offset = len(rows)
        rows += [
            JobEvent(offset + 1, "info", "mixed provider Apply command intended", {
                "invocationId": invocation, "argvSha256": initial_apply._digest(command),
                "planSha256": parent.events[index + 2].data["planSha256"],
                "planPath": plan_path, "terraformPath": command[0],
                "terraformSha256": "c" * 64}),
            JobEvent(offset + 2, "info", "mixed provider Apply command started before GO", {
                "invocationId": invocation, "bootId": "offline-test", "pid": 123,
                "pgid": 123, "startTicks": 10}),
            JobEvent(offset + 3, "info", "mixed provider phase apply_started",
                     {"commandStartSequence": offset + 2}),
            JobEvent(offset + 4, "info", "mixed provider Apply command result fenced", {
                "invocationId": invocation, "returnCode": 0, "stdoutBytes": 0,
                "stderrBytes": 0, "stdoutTruncated": False, "stderrTruncated": False}),
            JobEvent(offset + 5, "info", "mixed provider phase applied",
                     {"commandResultSequence": offset + 4}),
            JobEvent(offset + 6, "info", "mixed provider awaiting exact observation",
                     {"commandResultSequence": offset + 4}),
        ]
        node_id = str(index + 101)
        proof = {
            "classifierKind": "full", "stateSha256": "d" * 64,
            "lineage": f"offline-{provider}", "serial": 1,
            "inventorySha256": "e" * 64, "observationSha256": "f" * 64,
            "resourceIds": {"node.address": node_id},
            "selectorResourcesCount": 1 if provider == "digitalocean" else None,
            "selectorAttachedNodeIds": [node_id] if provider == "digitalocean" else None,
            "linodeFirewallAttachedNodeIds": [node_id] if provider == "linode" else None,
            "inventoryCount": 1,
            "commandResultJournalSha256": job_event_digest(rows[:offset + 4]),
        }
        rows += [
            JobEvent(offset + 7, "info", "mixed provider full observation proved", proof),
            JobEvent(offset + 8, "info", "mixed provider initial Apply succeeded",
                     {"observationSha256": proof["observationSha256"]}),
        ]
        child = StoredJobRun(
            initial_apply._child_id(core_job_id, provider), initial_apply.ACTION,
            "succeeded", f"engagement:{parent.target_id}", "engagement", parent.target_id,
            parent.requested_by, base, [], "2026-10-15T00:00:00+00:00",
            f"2026-10-15T00:00:0{index + 1}+00:00",
            f"2026-10-15T00:00:0{index + 2}+00:00", rows)
        case.jobs.save(child)
        children[provider] = case.jobs.get(child.id)
    terminals = [initial_apply.recognize_mixed_initial_apply_terminal(
        children[provider], parent, provider) for provider in order]
    handoff = replace(parent, input={**parent.input, "phase": HANDOFF_PHASE},
                      events=[*parent.events, JobEvent(7, "info", HANDOFF_MESSAGE,
                                                       _handoff_data(parent, terminals))])
    case.jobs.save(handoff)
    handoff = case.jobs.get(parent.id)
    core = case.jobs.get(core_job_id)
    assert recognize_mixed_initial_host_proof_handoff(
        handoff, core, core.id, children)["schema"] == "mixed-initial-host-proof-handoff-v1"
    return handoff, children


def _abandoned_no_go(case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    probes = {"count": 0}

    def first_then_changed(_source, _engagement, *, fence):
        fence()
        probes["count"] += 1
        return ("c" if probes["count"] == 1 else "e") * 64

    options["inspector_prover"] = first_then_changed
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    assert len(child.events) == 8 and actions == ["show", "apply"]
    expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    case.jobs.save(replace(child, input={**child.input, "claimExpiresAt": expired}))
    options["inspector_prover"] = lambda _s, _e, *, fence: (fence(), "c" * 64)[1]
    options.update(process_quiescent=lambda identity: True,
                   terraform_quiescent=lambda: True)
    return source, actions, options, captured


def test_interrupted_exact_eight_event_no_go_continues_once_and_proves_absence(
        case, monkeypatch):
    source, actions, options, _ = _abandoned_no_go(case, monkeypatch)
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    parent = case.jobs.get(child.input["teardownParentId"])
    preview = case.jobs.get(child.input["previewJobId"])
    assert apply_service.interrupted_apply_no_go_restartable(
        child, parent, preview, source.core_job_id,
        process_quiescent=lambda identity: True, terraform_quiescent=lambda: True)
    done = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert done.status == "succeeded" and done.id == child.id
    assert len(done.events) == 14 and actions == ["show", "apply", "apply"]
    assert done.events[8].message == "mixed core pre-GO Apply recovery claimed"
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)
    absence_service._authority(
        source.engagement_id, source.core_job_id, case.jobs,
        case.args["plan_repository"], options["lease_lookup"], interrupted=True)
    absent = absence_service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id,
        environment="devtest", state_root=case.state_root,
        core_state_root=case.core_state.parents[2], job_repository=case.jobs,
        plan_repository=case.args["plan_repository"],
        lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
        absence_prover=_absent, max_scans=2, poll_seconds=0, interrupted=True)
    assert absent.status == "succeeded"


@pytest.mark.parametrize("tamper", ["live", "terraform", "event", "state"])
def test_interrupted_no_go_rejects_uncertain_or_changed_evidence(
        case, monkeypatch, tamper):
    source, actions, options, _ = _abandoned_no_go(case, monkeypatch)
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    if tamper == "live":
        options["process_quiescent"] = lambda identity: False
    elif tamper == "terraform":
        options["terraform_quiescent"] = lambda: False
    elif tamper == "event":
        case.jobs.save(replace(child, events=[*child.events, JobEvent(
            9, "info", "core destroy GO support rechecked", {})]))
    else:
        case.core_state.write_text(case.core_state.read_text() + " ")
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True,
               "gated_command_runner": lambda *_a, **_k: pytest.fail("Terraform ran")})
    assert actions == ["show", "apply"]


def test_persisted_sqlalchemy_no_go_takeover_is_one_time_and_journal_cas(
        case, monkeypatch, tmp_path):
    source, _, options, _ = _abandoned_no_go(case, monkeypatch)
    original = case.jobs.get(apply_service._child_id(source.core_job_id))
    state = db.configure(f"sqlite:///{tmp_path / 'no-go-cas.sqlite'}")
    with db.bind(state):
        db.create_all()
        db.session.add(EngagementModel(
            id=source.engagement_id, name="opaque-fixture", status="active",
            owner="operator", template_id="small"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        jobs.save(original)
        stale = jobs.get(original.id)
        at = apply_service._now()
        owner = "provider-keyed-mixed-core-destroy-" + "a" * 32
        token = "b" * 32
        taken = jobs.take_over_mixed_core_apply_no_go(
            stale, expected_event_digest=job_event_digest(stale.events),
            owner=owner, token=token, claimed_at=at,
            expires_at=apply_service._later(at))
        assert taken is not None and len(taken.events) == 9
        assert taken.events[-1].data == {
            "originalJournalSha256": job_event_digest(stale.events),
            "originalInvocationId": stale.events[6].data["invocationId"],
        }
        assert jobs.take_over_mixed_core_apply_no_go(
            stale, expected_event_digest=job_event_digest(stale.events),
            owner=owner + "new", token=token + "new", claimed_at=at,
            expires_at=apply_service._later(at)) is None
    reopened = db.configure(state.uri)
    with db.bind(reopened):
        saved = SqlAlchemyJobRepository().get(original.id)
        assert saved.events == taken.events
        assert saved.input["claimToken"] == token


def test_persisted_sqlite_no_go_takeover_rejects_foreign_journal(
        case, monkeypatch):
    source, _, _, _ = _abandoned_no_go(case, monkeypatch)
    stale = case.jobs.get(apply_service._child_id(source.core_job_id))
    at = apply_service._now()
    kwargs = dict(expected_event_digest=job_event_digest(stale.events),
                  owner="provider-keyed-mixed-core-destroy-" + "a" * 32,
                  token="b" * 32, claimed_at=at,
                  expires_at=apply_service._later(at))
    tampered = list(stale.events)
    tampered[7] = replace(tampered[7], data={**tampered[7].data, "pid": 777})
    case.jobs.save(replace(stale, events=tampered))
    assert case.jobs.take_over_mixed_core_apply_no_go(stale, **kwargs) is None
    assert case.jobs.get(stale.id).events == tampered


def test_no_go_recovery_marker_blocks_a_third_apply_attempt(case, monkeypatch):
    source, actions, options, _ = _abandoned_no_go(case, monkeypatch)
    def veto_second_apply(*_args, **_kwargs):
        raise ValueError("offline pre-command veto")

    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True,
               "gated_command_runner": veto_second_apply})
    child = case.jobs.get(apply_service._child_id(source.core_job_id))
    assert len(child.events) == 9
    assert child.events[-1].message == "mixed core pre-GO Apply recovery claimed"
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True,
               "gated_command_runner": lambda *_a, **_k: pytest.fail("third attempt")})
    assert actions == ["show", "apply"]


def test_interrupted_preview_apply_and_exact_oci_absence_reuse_one_shot_journals(
        case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert applied.status == "succeeded" and actions == ["show", "apply"]
    assert applied.input["teardownParentId"] == captured["parent"].id
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)
    absent = absence_service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id,
        environment="devtest", state_root=case.state_root,
        core_state_root=case.core_state.parents[2], job_repository=case.jobs,
        plan_repository=case.args["plan_repository"],
        lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
        absence_prover=_absent, max_scans=2, poll_seconds=0, interrupted=True)
    assert absent.status == "succeeded"
    assert absent.input["teardownParentId"] == captured["parent"].id
    assert actions == ["show", "apply"]


def test_interrupted_absence_accepts_persisted_host_handoff_without_active_core_connection(
        case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    handoff, children = _persist_host_handoff(case, source.core_job_id)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert applied.status == "succeeded" and actions == ["show", "apply"]
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)
    args = dict(environment="devtest", state_root=case.state_root,
                core_state_root=case.core_state.parents[2], job_repository=case.jobs,
                plan_repository=case.args["plan_repository"],
                lease_lookup=options["lease_lookup"], identity_reader=lambda: {},
                absence_prover=_absent, max_scans=2, poll_seconds=0, interrupted=True)
    receipt = absence_service.prove_mixed_zero_apply_oci_core_absence(
        source.engagement_id, source.core_job_id, **args)
    assert receipt.status == "succeeded"
    assert receipt.input["teardownParentId"] == captured["parent"].id
    assert case.jobs.get(handoff.id).events[-1].message == HANDOFF_MESSAGE
    for provider in handoff.input["orderedProviders"]:
        assert case.jobs.get(children[provider].id).status == "succeeded"


def test_plan_only_validator_still_rejects_seven_event_interrupted_handoff(
        case, monkeypatch):
    source, _, _, _ = _interrupted_go_case(case, monkeypatch)
    handoff, _ = _persist_host_handoff(case, source.core_job_id)
    core = case.jobs.get(source.core_job_id)
    with pytest.raises(MixedInitialPlanParentError):
        _validate_parent(handoff, core, case.plan, handoff.input["chainIds"],
                         handoff.input["orderedProviders"])


@pytest.mark.parametrize("tamper", ["event", "terminal", "phase"])
def test_interrupted_absence_rejects_invalid_host_handoff_before_oci(
        case, monkeypatch, tamper):
    source, actions, options, _ = _interrupted_go_case(case, monkeypatch)
    handoff, children = _persist_host_handoff(case, source.core_job_id)
    apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    if tamper == "event":
        rows = list(handoff.events)
        rows[-1] = replace(rows[-1], data={**rows[-1].data, "firstFreshPresence": {}})
        case.jobs.save(replace(handoff, events=rows))
    elif tamper == "terminal":
        child = children[handoff.input["orderedProviders"][0]]
        case.jobs.save(replace(child, status="running", finished_at=None))
    else:
        case.jobs.save(replace(handoff, input={**handoff.input, "phase": "planning"}))
    with pytest.raises(absence_service.MixedZeroApplyCoreAbsenceAttention):
        absence_service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id,
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], job_repository=case.jobs,
            plan_repository=case.args["plan_repository"],
            lease_lookup=options["lease_lookup"],
            absence_prover=lambda *_a, **_k: pytest.fail("OCI scanned"),
            interrupted=True)
    assert case.jobs.get(absence_service._child_prefix(source.core_job_id)
                         + "-attempt-01") is None
    assert actions == ["show", "apply"]


def test_interrupted_queued_apply_restart_and_post_intent_no_replay(case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    original_save = case.jobs.save_if_absent

    def stopped_after_queue(child):
        original_save(child)
        raise RuntimeError("stopped after queue")

    monkeypatch.setattr(case.jobs, "save_if_absent", stopped_after_queue)
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True})
    assert actions == []
    queued = case.jobs.get(apply_service._child_id(source.core_job_id))
    assert queued.status == "queued" and len(queued.events) == 1
    monkeypatch.setattr(case.jobs, "save_if_absent", original_save)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    assert applied.status == "succeeded" and applied.id == queued.id
    assert actions == ["show", "apply"]
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True,
               "gated_command_runner": lambda *_a, **_k: pytest.fail("replayed")})
    assert actions == ["show", "apply"]


def test_interrupted_core_authority_drift_blocks_any_apply_command(case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    calls = 0
    original = captured["authority"]

    def changed(*args, **kwargs):
        nonlocal calls
        calls += 1
        return (original if calls == 1 else SimpleNamespace(
            **{**vars(original), "core_state_sha256": "0" * 64}))

    monkeypatch.setattr(apply_service, "audit_current_interrupted_oci_tail", changed)
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True,
               "gated_command_runner": lambda *_a, **_k: pytest.fail("Terraform ran")})
    assert calls >= 2 and actions == []


@pytest.mark.parametrize("forgery", ["zero_schema", "parent", "source", "inspector", "journal"])
def test_interrupted_apply_rejects_cross_mode_or_forged_preview_before_command(
        case, monkeypatch, forgery):
    source, actions, options, _ = _interrupted_go_case(case, monkeypatch)
    child = case.jobs.get(preview_service._child_id(source.core_job_id))
    if forgery == "zero_schema":
        forged = replace(child, input={**child.input, "schema": "mixed-zero-apply-core-preview-v1"})
    elif forgery == "parent":
        forged = replace(child, input={**child.input, "teardownParentId": "job-alien"})
    elif forgery == "source":
        forged = replace(child, input={**child.input, "sourceSha256": "0" * 64})
    elif forgery == "inspector":
        forged = replace(child, input={**child.input, "inspectorRecordIds": ["alien"]})
    else:
        forged = replace(child, events=[*child.events[:2], replace(
            child.events[2], data={**child.events[2].data, "sourceSha256": "0" * 64})])
    case.jobs.save(forged)
    with pytest.raises(apply_service.MixedZeroApplyCoreApplyAttention):
        apply_service.apply_mixed_zero_apply_oci_core_destroy(
            source.engagement_id, source.core_job_id,
            **{**options, "interrupted": True,
               "gated_command_runner": lambda *_a, **_k: pytest.fail("Terraform ran")})
    assert actions == []


def test_interrupted_absence_rejects_changed_pre_go_identity_before_oci(case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **{**options, "interrupted": True})
    _empty_state(case)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    rows = list(applied.events)
    rows[5] = replace(rows[5], data={**rows[5].data,
                                     "resourceIdsSha256": "0" * 64})
    case.jobs.save(replace(applied, events=rows))
    with pytest.raises(absence_service.MixedZeroApplyCoreAbsenceAttention):
        absence_service.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id,
            environment="devtest", state_root=case.state_root,
            core_state_root=case.core_state.parents[2], job_repository=case.jobs,
            plan_repository=case.args["plan_repository"],
            lease_lookup=options["lease_lookup"],
            absence_prover=lambda *_a, **_k: pytest.fail("OCI scanned"),
            interrupted=True)
    assert case.jobs.get(absence_service._child_prefix(source.core_job_id)
                         + "-attempt-01") is None
    assert actions == ["show", "apply"]


def test_private_one_action_oci_sequence_and_read_only_restart(case, monkeypatch):
    source, actions, options, captured = _interrupted_go_case(case, monkeypatch)
    monkeypatch.setattr(absence_service, "_default_state_root", lambda: case.state_root)
    monkeypatch.setattr(absence_service, "DEFAULT_TERRAFORM_STATE_ROOT",
                        case.core_state.parents[2])
    monkeypatch.setattr(absence_service, "_principal_digest", lambda _: "a" * 64)

    def apply_then_empty(engagement_id, core_job_id, **kwargs):
        result = apply_service.apply_mixed_zero_apply_oci_core_destroy(
            engagement_id, core_job_id, **{**options, "interrupted": True})
        _empty_state(case)
        return result

    def read_absence(engagement_id, core_job_id, **kwargs):
        return absence_service.prove_mixed_zero_apply_oci_core_absence(
            engagement_id, core_job_id, **kwargs,
            identity_reader=lambda: {}, absence_prover=_absent,
            max_scans=2, poll_seconds=0)

    common = dict(environment="devtest", state_root=case.state_root,
                  core_state_root=case.core_state.parents[2], job_repository=case.jobs,
                  plan_repository=case.args["plan_repository"],
                  lease_lookup=options["lease_lookup"])
    result = advance_mixed_interrupted_oci_core(
        source.engagement_id, source.core_job_id, **common,
        apply_core=apply_then_empty, prove_absence=read_absence)
    assert result.status == "succeeded" and actions == ["show", "apply"]
    again = advance_mixed_interrupted_oci_core(
        source.engagement_id, source.core_job_id, **common,
        preview_core=lambda *_a, **_k: pytest.fail("preview replayed"),
        apply_core=lambda *_a, **_k: pytest.fail("Apply replayed"),
        prove_absence=read_absence)
    assert again == result and actions == ["show", "apply"]
