# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted one-Deploy continuation through the real mixed publication writer.

The retained strict-proof child is fixture evidence here. Its raw SSH collection,
interpreter, and receipt validation are covered by their separate focused tests.
"""

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services import guarded_test_deployment
from app.services import provider_keyed_mixed_initial_public as public
from app.services import provider_keyed_mixed_initial_publication as publication
from app.storage.database import db
from app.storage.job_repository import job_event_digest
from app.storage.models import (
    CoreMutationLeaseModel, DeploymentPlanModel, JobEventModel, JobRunModel,
)
from test_provider_keyed_mixed_initial_publication_transaction import _mixed_case


def _completed_bootstrap_case(client, monkeypatch, tmp_path, *, reverse=False):
    """Move the SQL writer fixture back to the instant before host proof begins."""
    repo, jobs, leases, args = _mixed_case(client, monkeypatch)
    source = args["source"]
    if reverse:
        source = replace(source,
            ordered_providers=source.ordered_providers[::-1],
            chain_ids=source.chain_ids[::-1],
            provider_states=source.provider_states[::-1],
            host_rows=source.host_rows[2:] + source.host_rows[:2])
        args["pending_chains"] = args["pending_chains"][::-1]
        args["projected_chains"] = args["projected_chains"][::-1]
        plan = DeploymentPlanModel.query.filter_by(id="plan-core").one()
        plan.evidence = {**plan.evidence, "pendingSketchChainIds": list(source.chain_ids)}
        db.session.commit()
    mixed_parent = jobs.save(replace(args["parent"], id=public._parent_id("job-core"),
        input={**args["parent"].input,
               "orderedProviders": list(source.ordered_providers),
               "chainIds": list(source.chain_ids)}))
    args["parent"] = mixed_parent
    args["source"] = replace(source, parent_job_id=mixed_parent.id)
    args["receipt"].source = args["source"]
    core = jobs.get("job-core")
    jobs.save(replace(core, input={**core.input,
        "providerKeyedDispatchAuthorized": True,
        "pendingSketchChainIds": list(args["source"].chain_ids),
        "providerKeyedSourcePin": {"root": str(tmp_path), "revision": "pinned"}},
        events=[*core.events, JobEvent(len(core.events) + 1, "info",
            "pilot Standard RTI run finished", {
                "ok": True, "mutationStatus": "deployed",
                "ansibleStatus": "validated",
                "finalCleanupStatus": "pending_operator_teardown"})]))
    # The proof child is reserved by the collector, not present at dispatch.
    # Keep its exact persisted shape for the real writer and insert it once.
    old_child = args["proof_child"]
    source = args["source"]
    source_sha = hashlib.sha256(json.dumps(
        asdict(source), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    now = datetime.now(timezone.utc)
    proof_child = replace(old_child, id=public._proof_child_id("job-core"),
        started_at=now.isoformat(), input={
            "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
            "corePlanId": source.core_plan_id, "mixedParentId": source.parent_job_id,
            "handoffJournalSha256": source.parent_journal_sha256,
            "bindingJobId": "job-provider-keyed-mixed-host-binding-core",
            "bindingManifestSha256": source.binding_manifest_sha256,
            "bootstrapJobId": "job-provider-keyed-mixed-host-worker-core",
            "bootstrapJournalSha256": source.host_worker_journal_sha256,
            "mutation": False,
            "claimOwner": args["claim_owner"], "claimToken": args["claim_token"],
            "claimClaimedAt": (now - timedelta(minutes=1)).isoformat(),
            "claimExpiresAt": (now + timedelta(minutes=30)).isoformat(),
        }, events=[JobEvent(1, "info", "mixed strict host proof completed", {
            "sourceSha256": source_sha,
            "hostEvidenceSha256": args["receipt"].host_evidence_sha256,
        })])
    args["proof_child"] = proof_child
    args["receipt"].child_id = proof_child.id
    args["receipt"].child_event_sha256 = job_event_digest(proof_child.events)
    db.session.query(JobEventModel).filter_by(job_id=old_child.id).delete()
    db.session.query(JobRunModel).filter_by(id=old_child.id).delete()
    db.session.commit()
    monkeypatch.setattr(guarded_test_deployment, "_require_configured_keyed_source",
                        lambda pin: pin)
    monkeypatch.setattr(publication, "validate_mixed_initial_apply_seal",
                        lambda _parent: {"reviewedPolicy": {}})
    monkeypatch.setattr(publication, "recognize_mixed_initial_host_binding",
                        lambda _binding, _parent: {})
    monkeypatch.setattr(publication, "project_mixed_initial_chains",
                        lambda *_args: args["projected_chains"])
    monkeypatch.setattr(publication, "recognize_mixed_initial_apply_terminal",
                        lambda _child, _parent, provider: {"provider": provider})
    monkeypatch.setattr(publication, "_prior_workspace",
                        lambda _parent, provider, _terminal: SimpleNamespace(
                            path=Path(args["provider_workspaces"][provider])))
    contacts = []

    def collect(engagement_id, core_job_id, **_kwargs):
        contacts.append((engagement_id, core_job_id))
        assert jobs.get(proof_child.id) is None
        jobs.save(proof_child)
        return args["receipt"]

    monkeypatch.setattr(publication, "collect_mixed_initial_strict_host_proof", collect)
    return repo, jobs, leases, args, contacts


@pytest.mark.parametrize("reverse", [False, True], ids=["linode-first", "digitalocean-first"])
def test_completed_bootstrap_one_deploy_publishes_both_chains_and_restart_is_inert(
        client, monkeypatch, tmp_path, reverse):
    with client.application.storage_context():
        repo, jobs, leases, args, contacts = _completed_bootstrap_case(
            client, monkeypatch, tmp_path, reverse=reverse)
        parent = public.advance_reviewed_mixed_initial(
            "job-core", environment="devtest", rollout_enabled=True,
            job_repository=jobs)
        assert parent.status == "succeeded"
        assert parent.input["phase"] == "completed"
        assert jobs.get(args["proof_child"].id).status == "succeeded"
        assert contacts == [(args["source"].engagement_id, "job-core")]
        assert {row.chain_id: (row.status, row.terraform_working_directory) for row in
                repo.list_for_engagement(args["source"].engagement_id)} == {
            chain.chain_id: ("deployed", args["provider_workspaces"][chain.middle_provider])
            for chain in args["pending_chains"]}
        assert leases.acquire(args["source"].engagement_id, "next-plan", "prepare")
        scheduled = []
        assert public.recover_reviewed_mixed_initial_dispatches(
            environment="devtest", rollout_enabled=True,
            schedule=scheduled.append) == []
        assert scheduled == [] and len(contacts) == 1


def test_writer_rollback_marks_attention_without_recontact_or_partial_publication(
        client, monkeypatch, tmp_path):
    with client.application.storage_context():
        repo, jobs, _leases, args, contacts = _completed_bootstrap_case(
            client, monkeypatch, tmp_path)
        db.session.execute(text("""
            CREATE TRIGGER block_mixed_second_composed BEFORE UPDATE ON sketch_chains
            WHEN NEW.chain_id = 'proxy02-sfo-01'
            BEGIN SELECT RAISE(ABORT, 'injected failure'); END
        """))
        db.session.commit()
        with pytest.raises(publication.MixedInitialPublicationAttention,
                           match="reconciliation required"):
            public.advance_reviewed_mixed_initial(
                "job-core", environment="devtest", rollout_enabled=True,
                job_repository=jobs)
        assert contacts == [(args["source"].engagement_id, "job-core")]
        assert [row.status for row in repo.list_for_engagement(
            args["source"].engagement_id)] == ["pending", "pending"]
        assert jobs.get(args["parent"].id).input["phase"] == "attention"
        assert jobs.get(args["parent"].id).status == "failed"
        assert jobs.get(args["proof_child"].id).status == "failed"
        assert CoreMutationLeaseModel.query.filter_by(
            engagement_id=args["source"].engagement_id, owner_id="plan-core",
            operation="provider_keyed_initial").one_or_none() is not None
        scheduled = []
        assert public.recover_reviewed_mixed_initial_dispatches(
            environment="devtest", rollout_enabled=True,
            schedule=scheduled.append) == []
        assert scheduled == [] and len(contacts) == 1
