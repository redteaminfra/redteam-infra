# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published mixed provider absence binds empty state and fresh GET inventory."""

from dataclasses import replace
import hashlib
import json

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_published_absence import (
    PublishedMixedAbsenceAttention, prove_published_mixed_both_absent,
    prove_published_mixed_provider_absence,
    propose_published_mixed_first_absence_event,
)
from app.services.provider_keyed_mixed_published_destroy_child import (
    propose_published_mixed_destroy_child, recognize_published_mixed_destroy_child,
)
from app.services.provider_keyed_mixed_published_teardown_checkpoint import (
    propose_published_mixed_initial_cleanup, propose_published_mixed_plans_sealed,
)
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_interrupted_source import _snapshot
from test_provider_keyed_mixed_published_destroy_plan import _bind, _saved
from test_provider_keyed_mixed_published_teardown_checkpoint import _core_scope


def _awaiting(parent, review, plans, scope, provider, *, prior=None, engagement_name="Opaque"):
    child = propose_published_mixed_destroy_child(
        parent, review, plans, provider, scope, engagement_name,
        prior_absence_receipt_sha256=prior)
    plan = plans.plans[review.source.ordered_providers.index(provider)]
    rows = [*child.events]
    def add(message, data):
        rows.append(JobEvent(len(rows) + 1, "info", message, data))
    add("published mixed provider destroy started", {})
    add("published mixed provider destroy show proved", {
        "planSha256": plan.plan_sha256, "showSha256": plan.show_json_sha256,
        "beforeStateSha256": plan.before_state_sha256})
    add("published mixed provider destroy command intended", {
        "invocationId": "one-shot", "argvSha256": hashlib.sha256(json.dumps([
            plan.terraform_path, "apply", "-input=false", "-lock=true",
            "-no-color", plan.plan_path], separators=(",", ":")).encode()).hexdigest(),
        "showJournalSha256": job_event_digest(rows)})
    add("published mixed provider destroy command started before GO", {
        "invocationId": "one-shot", "bootId": "boot", "pid": 10,
        "pgid": 10, "startTicks": 20})
    add("published mixed provider destroy result fenced", {
        "invocationId": "one-shot", "returnCode": 0, "stdoutBytes": 0,
        "stderrBytes": 0, "stdoutTruncated": False, "stderrTruncated": False})
    add("published mixed provider awaiting exact absence", {
        "commandResultSequence": 6})
    return replace(child, status="running", started_at=child.created_at, events=rows)


def _empty_snapshot(plan):
    raw = json.dumps({
        "version": 4, "terraform_version": "1.15.5",
        "lineage": plan.state_lineage, "serial": plan.state_serial + 1,
        "resources": [],
    }).encode()
    return _snapshot(plan.provider, tag=plan.provider == "digitalocean",
                     phase="destroy_applied", state=raw)


def test_both_orders_prove_first_then_second_exact_absence(client, ready, tmp_path):
    with client.application.storage_context():
        review, initial, states, paths, shows = _saved(ready, tmp_path)
        plans = _bind(initial, review, states, paths, shows, tmp_path,
                      fence=lambda: "stable")
        scope = _core_scope(review)
        queued = propose_published_mixed_initial_cleanup(
            review, scope, "Opaque", requested_by="operator")
        parent = propose_published_mixed_plans_sealed(
            queued, review, plans, scope, "Opaque")
        first, second = review.source.ordered_providers
        first_child = _awaiting(parent, review, plans, scope, first)
        snapshots = {provider: _empty_snapshot(plan)
                     for provider, plan in zip(review.source.ordered_providers,
                                               plans.plans, strict=True)}
        kwargs = dict(core_inspector_scope=scope, engagement_name="Opaque",
                      fence=lambda: "stable", process_quiescent=lambda identity: True)
        first_receipt = prove_published_mixed_provider_absence(
            initial, parent, review, plans, first, first_child, snapshots[first], **kwargs)
        first_child = replace(first_child, status="succeeded",
                              finished_at=first_child.started_at, events=[
            *first_child.events,
            propose_published_mixed_first_absence_event(first_child, first_receipt)])
        assert recognize_published_mixed_destroy_child(
            first_child, parent, review, plans, first, scope, "Opaque") == "absence_proved"
        assert prove_published_mixed_provider_absence(
            initial, parent, review, plans, first, first_child,
            snapshots[first], **kwargs) == first_receipt
        second_child = _awaiting(parent, review, plans, scope, second,
                                 prior=first_receipt.receipt_sha256)
        receipts = prove_published_mixed_both_absent(
            initial, parent, review, plans,
            {first: first_child, second: second_child}, snapshots,
            scope, "Opaque", fence=lambda: "stable",
            process_quiescent=lambda identity: True)
        assert receipts[0] == first_receipt
        assert [receipt.provider for receipt in receipts] == [first, second]
        assert all(receipt.verified_absent_ids for receipt in receipts)
        with pytest.raises(PublishedMixedAbsenceAttention):
            prove_published_mixed_both_absent(
                initial, parent, review, plans,
                {first: replace(first_child, events=first_child.events[:7]),
                 second: second_child}, snapshots,
                scope, "Opaque", fence=lambda: "stable",
                process_quiescent=lambda identity: True)
        with pytest.raises(PublishedMixedAbsenceAttention):
            prove_published_mixed_both_absent(
                initial, parent, review, plans,
                {first: first_child, second: replace(second_child, input={
                    **second_child.input, "priorAbsenceReceiptSha256": "0" * 64})},
                snapshots, scope, "Opaque", fence=lambda: "stable",
                process_quiescent=lambda identity: True)
        with pytest.raises(PublishedMixedAbsenceAttention):
            prove_published_mixed_provider_absence(
                initial, parent, review, plans, first, first_child,
                replace(snapshots[first], inventory=({"id": "foreign"},)), **kwargs)
        with pytest.raises(PublishedMixedAbsenceAttention):
            prove_published_mixed_provider_absence(
                initial, parent, review, plans, first, first_child,
                snapshots[first], **{**kwargs,
                                   "process_quiescent": lambda identity: False})
        bad = replace(first_child, events=[*first_child.events[:-1], replace(
            first_child.events[-1], data={**first_child.events[-1].data,
                                          "receiptSha256": "0" * 64})])
        with pytest.raises(PublishedMixedAbsenceAttention):
            prove_published_mixed_provider_absence(
                initial, parent, review, plans, first, bad,
                snapshots[first], **kwargs)
