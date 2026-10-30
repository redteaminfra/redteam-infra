# Copyright (c) 2026, Oracle and/or its affiliates.
"""The public mixed proof handoff publishes only the complete two-provider set."""

from types import SimpleNamespace
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.services import provider_keyed_mixed_initial_publication as publication
from app.domain import JobEvent
from app.storage.job_repository import StoredJobRun


def test_completed_receipt_passes_two_provider_workspaces_to_one_writer(monkeypatch):
    source = SimpleNamespace(
        engagement_id="eng-opaque", core_job_id="job-core",
        chain_ids=("chain-linode", "chain-digitalocean"),
        ordered_providers=("linode", "digitalocean"),
        parent_journal_sha256="a" * 64,
    )
    receipt = SimpleNamespace(
        source=source, child_id="job-provider-keyed-mixed-strict-host-proof-core",
        child_event_sha256="b" * 64, claim_owner="owner", claim_token="token",
    )
    parent = SimpleNamespace(id="job-provider-keyed-mixed-initial-core")
    child = SimpleNamespace(id=receipt.child_id)
    binding = SimpleNamespace(id="job-provider-keyed-mixed-host-binding-core")
    applies = {provider: SimpleNamespace(id=f"apply-{provider}")
               for provider in source.ordered_providers}
    rows = {parent.id: parent, child.id: child, binding.id: binding,
            **{f"job-provider-keyed-mixed-initial-apply-{provider}-core": applies[provider]
               for provider in source.ordered_providers}}
    jobs = SimpleNamespace(get=rows.get)
    pending = {chain_id: SimpleNamespace(chain_id=chain_id)
               for chain_id in source.chain_ids}
    writes = []
    sketches = SimpleNamespace(
        get=lambda _engagement, chain_id: pending[chain_id],
        publish_provider_keyed_mixed_initial_chains=lambda **kwargs: writes.append(kwargs),
    )
    monkeypatch.setattr(publication, "collect_mixed_initial_strict_host_proof",
                        lambda *_args, **_kwargs: receipt)
    monkeypatch.setattr(publication, "validate_mixed_initial_apply_seal",
                        lambda _parent: {"reviewedPolicy": {}})
    monkeypatch.setattr(publication, "recognize_mixed_initial_host_binding",
                        lambda _binding, _parent: {})
    monkeypatch.setattr(publication, "project_mixed_initial_chains",
                        lambda *_args: ("linode-projection", "digitalocean-projection"))
    monkeypatch.setattr(publication, "recognize_mixed_initial_apply_terminal",
                        lambda child, _parent, provider: {"provider": provider,
                            "child": child.id})
    monkeypatch.setattr(publication, "_prior_workspace",
                        lambda _parent, provider, _terminal: SimpleNamespace(
                            path=f"/state/{provider}"))
    assert publication.publish_mixed_initial_strict_host_proof(
        "eng-opaque", "job-core", environment="devtest",
        job_repository=jobs, plan_repository=object(), sketch_repository=sketches) == parent
    assert len(writes) == 1
    assert writes[0]["provider_workspaces"] == {
        "linode": "/state/linode", "digitalocean": "/state/digitalocean"}
    assert writes[0]["pending_chains"] == (
        pending["chain-linode"], pending["chain-digitalocean"])
    assert writes[0]["claim_owner"] == "owner"
    assert writes[0]["claim_token"] == "token"


def test_incomplete_host_proof_never_reaches_writer(monkeypatch):
    writes = []
    sketches = SimpleNamespace(publish_provider_keyed_mixed_initial_chains=lambda **kwargs:
                               writes.append(kwargs))

    def incomplete(*_args, **_kwargs):
        raise ValueError("third host failed")

    monkeypatch.setattr(publication, "collect_mixed_initial_strict_host_proof", incomplete)
    with pytest.raises(ValueError, match="third host failed"):
        publication.publish_mixed_initial_strict_host_proof(
            "eng-opaque", "job-core", environment="devtest",
            job_repository=object(), plan_repository=object(), sketch_repository=sketches)
    assert writes == []


def test_failed_atomic_write_leaves_terminal_attention_without_recontact():
    at = datetime.now(timezone.utc).isoformat()
    parent_id = "job-provider-keyed-mixed-initial-core"
    child_id = "job-provider-keyed-mixed-strict-host-proof-core"
    common = {"claimOwner": "proof-owner", "claimToken": "proof-token"}
    parent = StoredJobRun(parent_id, "provider_keyed_mixed_initial", "running",
        "engagement:eng-opaque", "engagement", "eng-opaque", "operator",
        {**common, "phase": "awaiting_mixed_host_proof"}, [], at, at, None,
        [JobEvent(1, "info", "handoff", {})])
    child = replace(parent, id=child_id, action="provider_keyed_mixed_initial_strict_host_proof",
                    input=common, events=[JobEvent(1, "info", "proof complete", {})])
    rows = {parent_id: parent, child_id: child}

    class Jobs:
        def get(self, job_id):
            return rows.get(job_id)

        def finish_if_running_claimed(self, prior, **kwargs):
            assert prior == rows[prior.id]
            rows[prior.id] = replace(prior, status=kwargs["status"],
                                     finished_at=kwargs["finished_at"],
                                     events=[*prior.events, kwargs["event"]])
            return rows[prior.id]

        def save_if_leased(self, updated, **_kwargs):
            rows[updated.id] = updated
            return updated

    receipt = SimpleNamespace(child_id=child_id, claim_owner="proof-owner",
                              claim_token="proof-token")
    publication._mark_publication_attention(Jobs(), parent_id, receipt)
    assert rows[parent_id].status == rows[child_id].status == "failed"
    assert rows[parent_id].input["phase"] == "attention"
    assert rows[parent_id].events[-1].message.endswith("reconciliation required")
    assert rows[child_id].events[-1].message.endswith("reconciliation required")
    publication._mark_publication_attention(Jobs(), parent_id, receipt)
    assert len(rows[parent_id].events) == len(rows[child_id].events) == 2
