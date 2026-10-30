# Copyright (c) 2026, Oracle and/or its affiliates.
"""A stopped, sealed append can only resume its existing publication branch."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_append_publication_recovery import (
    ProviderKeyedAppendPublicationRecoveryConflict,
    publication_recovery_state,
    rearm_sealed_append_publication,
)
from app.storage.database import db
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_append_source import _pending_atomic_append_writer_case
from test_provider_keyed_append_host_producer import _case as _host_producer_case
import app.services.provider_keyed_append_host_proof_job as producer


def _stopped_case(client, tmp_path, monkeypatch):
    chains, args = _pending_atomic_append_writer_case(client, tmp_path, monkeypatch)
    jobs = SqlAlchemyJobRepository()
    parent = args["parent"]
    stopped = jobs.save(replace(
        parent, status="failed", finished_at=datetime.now(timezone.utc).isoformat(),
        input={**parent.input, "phase": "attention",
               "claimExpiresAt": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
               "mutation": True},
        events=[*parent.events, JobEvent(len(parent.events) + 1, "error",
            "strict append host proof stopped; reconciliation required", {})],
    ))
    return jobs, chains, stopped, args


def test_active_parent_has_no_recovery_hint(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        _, args = _pending_atomic_append_writer_case(client, tmp_path, monkeypatch)
        assert publication_recovery_state(args["parent"].id, state_root=tmp_path) == ""


def test_rearm_only_parent_and_preserve_all_child_journals(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, chains, parent, args = _stopped_case(client, tmp_path, monkeypatch)
        children = {key: jobs.get(parent.input[f"{key}JobId"])
                    for key in ("plan", "apply", "hostProof")}
        before = chains.list_for_engagement(parent.target_id)
        state_file = tmp_path / "provider" / "terraform.tfstate"
        state_bytes = state_file.read_bytes()
        assert publication_recovery_state(parent.id, state_root=tmp_path) == "ready"
        rearmed = rearm_sealed_append_publication(parent.id, state_root=tmp_path)
        assert rearmed.status == "running"
        assert rearmed.input["phase"] == "awaiting_publication"
        assert rearmed.finished_at is None
        assert rearmed.events[-2] == parent.events[-1]
        assert rearmed.events[-1].message == "strict append host proof completed"
        assert rearmed.events[-1].data == parent.events[-2].data
        assert not any(key.startswith("claim") for key in rearmed.input)
        assert {key: jobs.get(parent.input[f"{key}JobId"])
                for key in children} == children
        assert chains.list_for_engagement(parent.target_id) == before
        assert state_file.read_bytes() == state_bytes
        assert publication_recovery_state(parent.id, state_root=tmp_path) == ""
        with pytest.raises(ProviderKeyedAppendPublicationRecoveryConflict):
            rearm_sealed_append_publication(parent.id, state_root=tmp_path)


@pytest.mark.parametrize("change", [
    "live_claim", "prod", "state", "child", "lease", "row", "journal",
])
def test_rearm_fails_closed_on_changed_authority(client, tmp_path, monkeypatch, change):
    with client.application.storage_context():
        jobs, chains, parent, args = _stopped_case(client, tmp_path, monkeypatch)
        environment = "devtest"
        if change == "live_claim":
            parent = jobs.save(replace(parent, input={**parent.input,
                "claimExpiresAt": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}))
        elif change == "prod":
            environment = "prod"
        elif change == "state":
            (tmp_path / "provider" / "terraform.tfstate").write_text("changed")
        elif change == "child":
            child = jobs.get(parent.input["hostProofJobId"])
            jobs.save(replace(child, events=[*child.events,
                JobEvent(len(child.events) + 1, "info", "unexpected", {})]))
        elif change == "lease":
            db.session.get(CoreMutationLeaseModel, parent.target_id).owner_id = parent.id
            db.session.commit()
        elif change == "row":
            selected = chains.get(parent.target_id, parent.input["chainId"])
            chains.save(replace(selected, edge_count=2))
        elif change == "journal":
            jobs.save(replace(parent, events=[*parent.events[:-2], parent.events[-1]]))
        state = publication_recovery_state(parent.id, environment=environment,
                                           state_root=tmp_path)
        assert state == ("waiting" if change == "live_claim" else "")
        with pytest.raises(ProviderKeyedAppendPublicationRecoveryConflict):
            rearm_sealed_append_publication(parent.id, environment=environment,
                                             state_root=tmp_path)
        assert jobs.get(parent.id).status == "failed"


def test_rearm_cas_rejects_stale_review(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, _, parent, _ = _stopped_case(client, tmp_path, monkeypatch)
        changed = jobs.save(replace(parent, input={**parent.input, "unrelated": "change"}))
        assert jobs.rearm_sealed_provider_keyed_append_publication(
            parent, state_root=tmp_path) is None
        assert jobs.get(parent.id) == changed


def test_rearmed_parent_runs_existing_publication_only_branch_without_recontact(
        client, tmp_path, monkeypatch):
    with client.application.storage_context():
        jobs, chains, parent_id, before, other, after, calls, opts = \
            _host_producer_case(client, tmp_path, monkeypatch)
        original = chains.publish_provider_keyed_edge_append
        def stopped_after_seal(**_kwargs):
            raise KeyboardInterrupt("simulated crash after durable seal")
        monkeypatch.setattr(chains, "publish_provider_keyed_edge_append", stopped_after_seal)
        with pytest.raises(KeyboardInterrupt):
            producer.publish_reviewed_digitalocean_edge_append_host_proof(
                parent_id, **opts)
        monkeypatch.setattr(chains, "publish_provider_keyed_edge_append", original)
        sealed = jobs.get(parent_id)
        assert sealed.status == "running"
        assert sealed.events[-1].message == "strict append host proof completed"
        failed = jobs.save(replace(sealed, status="failed", input={**sealed.input,
            "phase": "attention",
            "claimExpiresAt": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()},
            finished_at=datetime.now(timezone.utc).isoformat(),
            events=[*sealed.events, JobEvent(len(sealed.events) + 1, "error",
                "strict append host proof stopped; reconciliation required", {})]))
        contact = [item for item in calls if item[0] in {"bootstrap", "probe"}]
        assert publication_recovery_state(parent_id, state_root=tmp_path) == "ready"
        rearmed = rearm_sealed_append_publication(parent_id, state_root=tmp_path)
        assert rearmed.events[-2] == failed.events[-1]
        result = producer.publish_reviewed_digitalocean_edge_append_host_proof(
            parent_id, **opts)
        assert result.status == "succeeded"
        assert chains.get(before.engagement_id, before.chain_id).edge_count == 2
        assert chains.get(other.engagement_id, other.chain_id) == other
        assert [item for item in calls if item[0] in {"bootstrap", "probe"}] == contact
