# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-Apply source cannot be confused with a stopped/uncertain provider write."""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import json

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_unapplied_append_teardown as noapply
from app.services.provider_keyed_mixed_append_pair_parent import (
    _parent_id, _plan_child_id, mixed_append_review_summary, mixed_append_approval_sha256,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import reopen_mixed_append_pair_plan_review
from app.services.provider_keyed_mixed_append_published_source import PublishedMixedAppendSource
from app.storage.job_repository import StoredJobRun
from test_provider_keyed_mixed_append_pair_plan_worker import fixture as plan_fixture


def rows(core="job-core", plan="plan-core", engagement="eng-test", phase="planning", review_sha="a" * 64):
    at = "2026-10-19T00:00:00+00:00"
    parent_id = _parent_id(core)
    data = {"schema": "mixed-append-pair-parent-v1", "engagementId": engagement,
        "coreJobId": core, "corePlanId": plan, "phase": phase, "mutation": True,
        "providerOrder": ["digitalocean", "linode"], "chainOrder": ["chain-li", "chain-do"],
        "reviewRequest": {"digitalocean": {"selectedChainId": "chain-li", "edgeRegion": "nyc3", "edgeSize": "small"},
                          "linode": {"selectedChainId": "chain-do", "edgeRegion": "us-east", "edgeType": "small"}}, "requestSha256": "b" * 64, "reviewSummary": {}}
    events = [JobEvent(1, "info", "mixed append pair reserved", {"requestSha256": data["requestSha256"]}),
              JobEvent(2, "info", "mixed append pair planning started", {})]
    if phase == "apply_sealed":
        data["reviewSha256"] = review_sha
        events.append(JobEvent(3, "info", "mixed append pair approved",
            {"reviewSha256": review_sha, "planChildId": _plan_child_id(parent_id)}))
    parent = StoredJobRun(parent_id, "provider_keyed_mixed_append", "running",
        f"engagement:{engagement}", "engagement", engagement, "operator", data, [], at, at, None, events)
    child = replace(parent, id=_plan_child_id(parent_id), action="provider_keyed_mixed_append_plan_child",
        status="succeeded", finished_at=at, input={"schema": "mixed-append-pair-plan-v1",
        "appendParentId": parent.id, "engagementId": engagement, "coreJobId": core,
        "corePlanId": plan, "mutation": False, "requestSha256": data["requestSha256"]}, events=[
            JobEvent(1, "info", "mixed append pair plan reserved", {"requestSha256": data["requestSha256"]}),
            JobEvent(2, "info", "mixed append pair plan started", {}),
            JobEvent(3, "info", "mixed append pair plan reviewed", {"reviewSha256": review_sha})])
    stored = {parent.id: parent, child.id: child}
    return parent, child, stored, SimpleNamespace(get=lambda identifier: stored.get(identifier))


@pytest.mark.parametrize("phase", ["planning", "apply_sealed"])
def test_exact_no_apply_journals_require_no_continuation_or_live_claim(phase):
    parent, plan, stored, jobs = rows(phase=phase)
    assert noapply.no_apply_present(parent, jobs)
    for identifier in (noapply.first_id(parent.id), noapply.second_id(parent.id), noapply.host_id(parent.id)):
        stored[identifier] = replace(plan, id=identifier)
        assert not noapply.no_apply_present(parent, jobs)
        del stored[identifier]
    live = replace(parent, input={**parent.input,
        "claimExpiresAt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()})
    assert not noapply.no_apply_present(live, jobs)
    assert not noapply.no_apply_present(replace(parent, events=parent.events + [JobEvent(
        len(parent.events) + 1, "info", "unknown", {})]), jobs)


def authenticated(tmp_path, monkeypatch):
    options, _, _ = plan_fixture(tmp_path, monkeypatch)
    source = options["source"]
    published = PublishedMixedAppendSource(source,
        tuple((provider, workspace.path) for provider, workspace in options["workspaces"].items()),
        0, "d" * 64, "e" * 64)
    seal = reopen_mixed_append_pair_plan_review(**options)
    digest = mixed_append_approval_sha256(seal.review_sha256, published)
    parent, child, stored, jobs = rows(source.core_job_id, source.core_plan_id, source.engagement_id,
        review_sha=digest)
    parent = replace(parent, input={**parent.input, "providerOrder": list(options["reviewed_provider_order"]),
        "chainOrder": list(options["reviewed_chain_order"])})
    # The fixture's request is server-owned; tests below exercise the real saved
    # plan reopener while source-context authentication has its own service suite.
    from app.services.provider_keyed_mixed_append_pair_parent import _matches_request
    do, li = options["digitalocean_intent"], options["linode_intent"]
    request = {"digitalocean": {"selectedChainId": do.chain_id, "edgeRegion": do.new_edge.region,
        "edgeSize": do.new_edge.size, "edgeImage": do.new_edge.image, "selectorTag": do.new_edge.firewall_selector_tag},
        "linode": {"selectedChainId": li.chain_id, "edgeRegion": li.new_edge.region,
        "edgeType": li.new_edge.node_type, "edgeImage": li.new_edge.image, "engagementTag": li.new_edge.tag}}
    parent = replace(parent, input={**parent.input, "reviewRequest": request})
    parent = replace(parent, input={**parent.input, "reviewSummary": mixed_append_review_summary(parent, seal)})
    stored[parent.id] = parent
    context = SimpleNamespace(source=source, workspaces=options["workspaces"],
        reviewed_provider_order=options["reviewed_provider_order"], reviewed_chain_order=options["reviewed_chain_order"],
        approval_kwargs=lambda: {key: value for key, value in options.items() if key in {
            "binding_manifest", "digitalocean_intent", "linode_intent", "workspaces", "provider_states",
            "reviewed_inputs", "digitalocean_firewall"}})
    monkeypatch.setattr("app.services.provider_keyed_mixed_append_plan_context.collect_mixed_append_pair_plan_context",
        lambda *args, **kwargs: context)
    monkeypatch.setattr("app.services.provider_keyed_mixed_append_published_source.collect_published_mixed_append_source",
        lambda *args, **kwargs: published)
    monkeypatch.setattr(noapply, "_process_quiescent", lambda *args: True)
    initial = replace(parent, id=source.parent_job_id, action="provider_keyed_mixed_initial")
    review = SimpleNamespace(source=source)
    kwargs = dict(jobs=jobs, workspaces=options["workspaces"], credentials=options["credential_repository"],
        lease_lookup=lambda _: (source.core_plan_id, "provider_keyed_mixed_append"), release_check=options["release_check"])
    return review, initial, parent, stored, kwargs


def test_real_saved_plan_reopen_and_immutable_history_survive_destroyed_current_state(tmp_path, monkeypatch):
    review, initial, parent, stored, kwargs = authenticated(tmp_path, monkeypatch)
    recovery = noapply.build_no_apply_recovery(review, initial, parent, **kwargs)
    assert recovery["kind"] == noapply.KIND and recovery["failedProvider"] is None
    reviewed = SimpleNamespace(source=review.source, failed_append_recovery=recovery)
    for workspace in kwargs["workspaces"].values():
        workspace.state_path.write_bytes(b"destroyed state no longer needed for historical proof")
    assert noapply.no_apply_history(reviewed, jobs=kwargs["jobs"], workspaces=kwargs["workspaces"], initial=initial) == recovery["evidence"]
    stored[noapply.first_id(parent.id)] = replace(parent, id=noapply.first_id(parent.id), events=[JobEvent(1, "info", "command intended", {})])
    with pytest.raises(ValueError):
        noapply.no_apply_history(reviewed, jobs=kwargs["jobs"], workspaces=kwargs["workspaces"], initial=initial)


@pytest.mark.parametrize("tamper", ["plan", "quiescence", "review"])
def test_no_apply_authentication_rejects_drift(tmp_path, monkeypatch, tamper):
    review, initial, parent, stored, kwargs = authenticated(tmp_path, monkeypatch)
    if tamper == "plan":
        (next(iter(kwargs["workspaces"].values())).path / noapply._name("digitalocean", "saved.tfplan")).write_bytes(b"changed")
    elif tamper == "quiescence":
        monkeypatch.setattr(noapply, "_process_quiescent", lambda *args: False)
    else:
        child = stored[_plan_child_id(parent.id)]
        stored[child.id] = replace(child, events=[*child.events[:2], replace(child.events[2], data={"reviewSha256": "0" * 64})])
    with pytest.raises(ValueError):
        noapply.build_no_apply_recovery(review, initial, parent, **kwargs)


def test_exact_successful_review_retry_is_still_no_apply():
    parent, plan, stored, jobs = rows()
    plan = replace(plan, events=[*plan.events[:2],
        JobEvent(3, "error", "mixed append pair plan needs reconciliation", {}),
        JobEvent(4, "info", "mixed append pair Review retry requested", {"completedPlansOnly": True}),
        JobEvent(5, "info", "mixed append pair plan started", {}),
        JobEvent(6, "info", "mixed append pair plan reviewed", {"reviewSha256": "a" * 64})])
    stored[plan.id] = plan
    assert noapply.no_apply_present(parent, jobs)
    stored[plan.id] = replace(plan, events=[*plan.events[:3],
        replace(plan.events[3], data={"unknown": True}), *plan.events[4:]])
    assert not noapply.no_apply_present(parent, jobs)


def test_incomplete_claim_cannot_be_treated_as_expired():
    parent, _, _, jobs = rows()
    assert not noapply.no_apply_present(replace(parent, input={**parent.input,
        "claimOwner": "unknown", "claimToken": "unknown"}), jobs)
