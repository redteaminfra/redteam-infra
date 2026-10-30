# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted zero-result, poststate, and restart tests for provider two."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_append_second_apply_child import (
    ACTION, _base, _child_id,
)
import app.services.provider_keyed_mixed_append_second_proof_job as service
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_mixed_append_first_poststate import _case


def _ready(provider):
    state = db.configure("sqlite:///:memory:")
    with db.bind(state):
        db.create_all()
        db.session.add(CoreMutationLeaseModel(
            engagement_id="eng-one", owner_id="plan-core",
            operation="provider_keyed_mixed_append"))
        db.session.commit()
        jobs = SqlAlchemyJobRepository()
        now = datetime.now(timezone.utc).isoformat()
        prior = _case(provider)
        parent = StoredJobRun(
            "job-pair", "provider_keyed_mixed_append", "running",
            "engagement:eng-one", "engagement", "eng-one", "operator",
            {"schema": "mixed-append-pair-parent-v1", "phase": "apply_sealed",
             "coreJobId": "job-core", "corePlanId": "plan-core",
             "reviewSha256": "a" * 64,
             "providerOrder": ["linode" if provider == "digitalocean" else "digitalocean",
                               provider]},
            [], now, now, None, [JobEvent(1, "info", "mixed append pair approved", {})])
        jobs.save(parent)
        messages = [
            ("mixed append second Apply queued", {}),
            ("mixed append second Apply started", {}),
            ("mixed append second Apply command intended", {
                "invocationId": "two", "argvSha256": "d" * 64,
                "planSha256": "b" * 64, "planPath": "/saved.tfplan",
                "terraformPath": "/terraform", "terraformSha256": "c" * 64}),
            ("mixed append second Apply command started before GO", {
                "invocationId": "two", "bootId": "boot", "pid": 123,
                "pgid": 123, "startTicks": 99}),
            ("mixed append second phase apply_started", {"commandStartSequence": 4}),
            ("mixed append second Apply command result fenced", {
                "invocationId": "two", "returnCode": 0,
                "stdoutBytes": 0, "stderrBytes": 0,
                "stdoutTruncated": False, "stderrTruncated": False}),
            ("mixed append second phase applied", {"commandResultSequence": 6}),
            ("mixed append second awaiting exact poststate proof", {
                "commandResultSequence": 6}),
        ]
        child = StoredJobRun(
            _child_id(parent.id), ACTION, "running", parent.target,
            parent.target_type, parent.target_id, parent.requested_by,
            _base(parent), [], now, now, None,
            [JobEvent(index, "info", message, data)
             for index, (message, data) in enumerate(messages, 1)])
        jobs.save(child)
        receipt = {"provider": provider, "engagementId": "eng-one",
                   "coreJobId": "job-core", "planSha256": "b" * 64,
                   "terraformBinarySha256": "c" * 64,
                   "predecessorStateSha256": hashlib.sha256(
                       prior["predecessor_state"]).hexdigest()}
        source = SimpleNamespace(
            intent=prior["intent"], receipt=receipt,
            receipt_sha256="e" * 64,
            predecessor_state=prior["predecessor_state"],
            reviewed_show_json=prior["reviewed_show_json"],
            workspace=object())
    return state, jobs, parent, child, prior, source


def _options(jobs, parent, source, snapshots):
    values = iter(snapshots)
    return dict(
        parent_id=parent.id, environment="devtest", job_repository=jobs,
        lease_lookup=lambda engagement: (
            (row.owner_id, row.operation) if (
                row := db.session.get(CoreMutationLeaseModel, engagement)) else None),
        source_loader=lambda selected, repository, release: source,
        first_terminal_proof=lambda selected, renew: "f" * 64,
        snapshot_collector=lambda **kwargs: next(values),
        process_quiescent=lambda _: True,
        max_observation_attempts=len(snapshots) or 1,
        poll_interval_seconds=0, sleeper=lambda _: None,
    )


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_second_provider_proof_persists_exact_event_then_terminal(provider):
    state, jobs, parent, child, prior, source = _ready(provider)
    with db.bind(state):
        terminal = service.prove_and_finish_second_mixed_append_apply(
            **_options(jobs, parent, source, [prior["snapshot"]]))
        assert terminal.status == "succeeded"
        assert [event.sequence for event in terminal.events] == list(range(1, 11))
        assert terminal.events[8].data["provider"] == provider
        assert terminal.events[8].data["firstProofJournalSha256"] == "f" * 64
        assert jobs.get(child.id) == terminal
        again = service.prove_and_finish_second_mixed_append_apply(
            **_options(jobs, parent, source, []))
        assert again == terminal


def test_crash_after_proof_event_reobserves_before_terminal(monkeypatch):
    state, jobs, parent, child, prior, source = _ready("linode")
    with db.bind(state):
        finish = jobs.finish_if_running_claimed
        monkeypatch.setattr(jobs, "finish_if_running_claimed", lambda *a, **k: None)
        with pytest.raises(service.MixedAppendSecondProofJobAttention):
            service.prove_and_finish_second_mixed_append_apply(
                **_options(jobs, parent, source, [prior["snapshot"]]))
        persisted = jobs.get(child.id)
        assert persisted.status == "running" and len(persisted.events) == 9
        monkeypatch.setattr(jobs, "finish_if_running_claimed", finish)
        changed = replace(prior["snapshot"], state_sha256="0" * 64)
        with pytest.raises(service.MixedAppendSecondProofJobAttention):
            service.prove_and_finish_second_mixed_append_apply(
                **_options(jobs, parent, source, [changed]),
                claim_owner=persisted.input["claimOwner"],
                claim_token=persisted.input["claimToken"])
        assert len(jobs.get(child.id).events) == 9
        terminal = service.prove_and_finish_second_mixed_append_apply(
            **_options(jobs, parent, source, [prior["snapshot"]]),
            claim_owner=persisted.input["claimOwner"],
            claim_token=persisted.input["claimToken"])
        assert terminal.status == "succeeded"


@pytest.mark.parametrize("drift", ["uncertain_result", "lease", "first_proof", "poststate"])
def test_uncertainty_or_drift_never_records_second_proof(drift):
    state, jobs, parent, child, prior, source = _ready("digitalocean")
    with db.bind(state):
        if drift == "uncertain_result":
            events = list(child.events)
            events[5] = replace(events[5], data={**events[5].data, "returnCode": 1})
            jobs.save(replace(child, events=events))
        elif drift == "lease":
            db.session.get(CoreMutationLeaseModel, parent.target_id).operation = "other"
            db.session.commit()
        elif drift == "poststate":
            prior["snapshot"] = replace(prior["snapshot"], state_sha256="0" * 64)
        options = _options(jobs, parent, source, [prior["snapshot"]])
        if drift == "first_proof":
            options["first_terminal_proof"] = lambda selected, renew: "changed"
        with pytest.raises(service.MixedAppendSecondProofJobAttention):
            service.prove_and_finish_second_mixed_append_apply(**options)
        assert len(jobs.get(child.id).events) == 8


def test_tampered_persisted_proof_cannot_be_reused():
    state, jobs, parent, child, prior, source = _ready("digitalocean")
    with db.bind(state):
        terminal = service.prove_and_finish_second_mixed_append_apply(
            **_options(jobs, parent, source, [prior["snapshot"]]))
        events = list(terminal.events)
        events[8] = replace(events[8], data={**events[8].data,
                                            "newEdgeProviderId": "other"})
        jobs.save(replace(terminal, events=events))
        with pytest.raises(service.MixedAppendSecondProofJobAttention):
            service.prove_and_finish_second_mixed_append_apply(
                **_options(jobs, parent, source, []))


def test_first_provider_drift_after_second_get_blocks_proof_event():
    state, jobs, parent, child, prior, source = _ready("linode")
    calls = []

    def first_check(selected, renew):
        calls.append(1)
        return "f" * 64 if len(calls) < 3 else "e" * 64

    with db.bind(state):
        options = _options(jobs, parent, source, [prior["snapshot"]])
        options["first_terminal_proof"] = first_check
        with pytest.raises(service.MixedAppendSecondProofJobAttention):
            service.prove_and_finish_second_mixed_append_apply(**options)
        assert len(calls) == 3
        assert len(jobs.get(child.id).events) == 8
