# Copyright (c) 2026, Oracle and/or its affiliates.
"""The opt-in Inspector provider stage journal is a finite, claimed CAS."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from app.domain import JobEvent
from app.storage.job_repository import inspector_claim_generation_digest, job_event_digest
from test_job_repository_claimed_apply import repository
from test_job_repository_keyed_inspector_intent import DATA, append, claim, row


OWNER = "provider-keyed-inspector-create"
TOKEN = "a" * 32


def prepared(repo, provider="digitalocean"):
    repo.save(row())
    current = claim(repo)
    assert current is not None
    current = append(repo, current, data={**DATA, "provider": provider})
    assert current is not None
    return current


def stage_event(current, *, stage, point, resource_id="", firewall_id="", droplet_id="", **changes):
    provider = current.events[4].data["provider"]
    name = current.events[4].data["resourceName"]
    data = {
        "provider": provider, "resourceName": name, "stage": stage, "point": point,
        "resourceId": resource_id, "firewallId": firewall_id,
        "dropletId": droplet_id,
        "tagName": "bi-" + hashlib.sha256(name.encode()).hexdigest()[:20]
        if provider == "digitalocean" else "",
        "tagExclusive": False,
    }
    data.update(changes)
    return JobEvent(len(current.events) + 1, "info", "inspector_create_stage", data)


def add(repo, current, event, *, heartbeat=None, token=TOKEN, digest=None):
    now = datetime.now(timezone.utc)
    return repo.append_keyed_inspector_stage_if_running_claimed(
        current, owner=OWNER, token=token,
        expected_event_digest=digest or job_event_digest(current.events),
        heartbeat_at=heartbeat or now.isoformat(),
        expires_at=(now + timedelta(minutes=5)).isoformat(), event=event,
    )


def complete(repo, current, provider):
    if provider == "linode":
        steps = [
            ("firewall", "before_post", "", "", ""),
            ("firewall", "response_received", "42", "", ""),
            ("instance", "before_post", "", "42", ""),
            ("instance", "response_received", "123", "42", ""),
        ]
    else:
        steps = [
            ("tag", "before_post", "", "", ""),
            ("tag", "response_received", "", "", ""),
            ("firewall", "before_post", "", "", ""),
            ("firewall", "response_received", "fw-42", "fw-42", ""),
            ("droplet", "before_post", "", "fw-42", ""),
            ("droplet", "response_received", "456", "fw-42", "456"),
            ("attachment", "before_post", "", "fw-42", "456"),
            ("attachment", "response_received", "", "fw-42", "456"),
        ]
    for stage, point, rid, fid, did in steps:
        prior = current
        current = add(repo, current, stage_event(current, stage=stage, point=point,
                                                 resource_id=rid, firewall_id=fid, droplet_id=did))
        assert current is not None
        assert current.events[:-1] == prior.events
    return current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("provider", ["linode", "digitalocean"])
def test_exact_finite_stage_journal(kind, provider, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = complete(repo, prepared(repo, provider), provider)
        assert len(current.events) == (9 if provider == "linode" else 13)
        assert add(repo, current, stage_event(current, stage="attachment", point="before_post")) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("change", [
    lambda e: replace(e, data={**e.data, "stage": "droplet"}),
    lambda e: replace(e, data={**e.data, "resourceName": "inspector-" + "f" * 32}),
    lambda e: replace(e, data={**e.data, "providerToken": "secret"}),
    lambda e: replace(e, data={**e.data, "tagExclusive": True}),
    lambda e: replace(e, data={**e.data, "resourceId": []}),
])
def test_first_stage_malformed_veto(kind, change, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = prepared(repo)
        event = change(stage_event(current, stage="tag", point="before_post"))
        assert add(repo, current, event) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_order_and_cross_stage_ids_veto(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = prepared(repo)
        first = stage_event(current, stage="tag", point="before_post")
        current = add(repo, current, first)
        assert current is not None
        assert add(repo, current, stage_event(current, stage="tag", point="before_post")) is None
        current = add(repo, current, stage_event(current, stage="tag", point="response_received"))
        current = add(repo, current, stage_event(current, stage="firewall", point="before_post"))
        assert current is not None
        assert add(repo, current, stage_event(current, stage="firewall", point="response_received",
                                              resource_id="fw-42", firewall_id="wrong")) is None
        current = add(repo, current, stage_event(current, stage="firewall", point="response_received",
                                                 resource_id="fw-42", firewall_id="fw-42"))
        assert current is not None
        assert add(repo, current, stage_event(current, stage="droplet", point="before_post",
                                              firewall_id="fw-other")) is None


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_stale_claim_and_same_count_rewrite_rollback(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = prepared(repo)
        event = stage_event(current, stage="tag", point="before_post")
        assert add(repo, current, event, token="b" * 32) is None
        rewritten = replace(current, events=[JobEvent(1, "info", "rewritten", {}), *current.events[1:]])
        repo.save(rewritten)
        assert add(repo, current, event) is None
        assert repo.get(current.id) == rewritten


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_two_writers_same_generation_only_one_appends(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = prepared(repo)
        event = stage_event(current, stage="tag", point="before_post")
        winner = add(repo, current, event)
        assert winner is not None
        assert add(repo, current, event) is None
        assert repo.get(current.id) == winner


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_earlier_stage_id_rewrite_vetoes_next_append(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = prepared(repo)
        current = add(repo, current, stage_event(current, stage="tag", point="before_post"))
        assert current is not None
        event = stage_event(current, stage="tag", point="response_received")
        events = list(current.events)
        events[5] = replace(events[5], data={**events[5].data, "resourceName": "inspector-" + "f" * 32})
        rewritten = replace(current, events=events)
        repo.save(rewritten)
        assert add(repo, current, event) is None
        assert add(repo, rewritten, event) is None
        assert repo.get(current.id) == rewritten


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
def test_actual_expiry_rejects_backdated_heartbeat(kind, tmp_path):
    with repository(kind, tmp_path) as repo:
        repo.save(row())
        current = claim(repo, expired=True)
        # The intent method itself rejects an expired claim, so build an exact
        # historical started row for the DB-clock stage predicate regression.
        old = datetime.now(timezone.utc) - timedelta(minutes=2, seconds=30)
        current = replace(current, input={**current.input, "phase": "inspector_create_started"},
                          events=[*current.events, JobEvent(5, "info", "inspector_create_started", {
                              **DATA, "claimGenerationSha256": inspector_claim_generation_digest(
                                  token=current.input["claimToken"],
                                  claimed_at=current.input["claimClaimedAt"]),
                          })])
        repo.save(current)
        event = stage_event(current, stage="tag", point="before_post")
        assert add(repo, current, event, heartbeat=old.isoformat()) is None
        assert repo.get(current.id) == current


@pytest.mark.parametrize("kind", ["sqlite", "sqlalchemy"])
@pytest.mark.parametrize("intent_change", [
    {"credentialUpdatedAt": "yesterday"},
    {"managementSourceCidr": "224.0.0.1/32"},
])
def test_malformed_intent_is_not_stage_authority(kind, intent_change, tmp_path):
    with repository(kind, tmp_path) as repo:
        current = prepared(repo)
        events = list(current.events)
        events[4] = replace(events[4], data={**events[4].data, **intent_change})
        malformed = replace(current, events=events)
        repo.save(malformed)
        assert add(repo, malformed, stage_event(malformed, stage="tag", point="before_post")) is None
