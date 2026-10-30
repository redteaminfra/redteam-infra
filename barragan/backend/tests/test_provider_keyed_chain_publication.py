# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network SQLAlchemy transaction proof for dormant v2 two-chain publication."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.domain import JobEvent
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_host_proof import HostEvidenceValidation
from app.services.provider_keyed_strict_host_proof import StrictHostSetProof
from app.services.post_core_sketch_continuation import sketch_chain_intent_fingerprint
from app.integrations.oci_deployment_targets import normalized_oci_deployment_target
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.models import DeploymentPlanModel, EngagementModel, JobEventModel
from app.storage.sketch_chain_repository import (
    ProviderKeyedPublicationConflict, SqlAlchemySketchChainRepository,
)
from app.storage.database import db
from test_provider_keyed_chain_projection import _fixture


def _case(client, *, workspace_path="/private/tmp/provider-keyed-test-workspace"):
    reviewed, attachment, attachment_proof, chains = _fixture()
    projections = project_digitalocean_initial_chains(reviewed, attachment, attachment_proof, chains)
    repo = SqlAlchemySketchChainRepository()
    jobs = SqlAlchemyJobRepository()
    leases = SqlAlchemyDeploymentPlanRepository()
    pending = tuple(repo.save(chain) for chain in chains)
    projections = tuple(replace(item, chain=replace(pending[index], nodes=item.chain.nodes))
                        for index, item in enumerate(projections))
    core_id = "job-core"
    plan_id = "plan-core"
    workspace = workspace_path
    fingerprints = {chain.chain_id: sketch_chain_intent_fingerprint(chain) for chain in pending}
    target = normalized_oci_deployment_target("barragan-testing")
    db.session.add(EngagementModel(
        id=reviewed.engagement_id, name="opaque-test", status="deployed",
        owner="operator", template_id="small-dev", active_revision="rev-1",
        input_parameters={"deploymentTarget": target}, sketch_state_schema="provider-keyed-v2",
    ))
    db.session.add(DeploymentPlanModel(
        id=plan_id, engagement_id=reviewed.engagement_id, revision_id="rev-1",
        status="applied", stage="applied", review={},
        evidence={"sketchStateSchema": "provider-keyed-v2",
                  "pendingSketchChainIds": [chain.chain_id for chain in pending],
                  "pendingSketchChainFingerprints": fingerprints},
        is_current=False, apply_job_id="job-core", error="",
    ))
    db.session.commit()
    manifest = {
        "engagementId": reviewed.engagement_id, "coreJobId": core_id,
        "corePlanId": plan_id, "stateSha256": attachment.state_sha256,
        "coreKnownHostsPath": "/pinned/core/known_hosts",
        "coreKnownHostsSha256": "f" * 64,
        "sketchKnownHostsPath": workspace + "/.barragan-sketch-known-hosts",
        "chainFingerprints": [{"chainId": chain.chain_id,
                               "fingerprint": fingerprints[chain.chain_id]} for chain in pending],
        "hostPolicies": [{"chainId": item.chain.chain_id,
                          "proxyEgressIp": item.proxy_egress_ip,
                          "hosts": item.host_policies} for item in projections],
        "nodes": sorted(({
            "chainId": row["chainId"], "role": row["role"],
            "providerInstanceId": row["providerInstanceId"],
            "terraformAddress": row["terraformAddress"],
            "name": row["hostname"], "publicIp": row["publicIp"],
            "region": row["region"],
        } for item in projections for row in item.chain.nodes),
            key=lambda row: row["terraformAddress"]),
    }
    digest = _digest_json(manifest)
    now = datetime.now(timezone.utc)
    claim_at = (now - timedelta(minutes=1)).isoformat()
    finish_at = now.isoformat()
    expiry = (now + timedelta(minutes=30)).isoformat()
    jobs.save(StoredJobRun(
        id=core_id, action="pilot_standard_rti_guarded_execute", status="succeeded",
        target="oci-compartment:barragan-testing", target_type="oci_compartment",
        target_id=target["compartmentId"], requested_by="operator",
        input={"engagementId": reviewed.engagement_id, "corePlanId": plan_id,
               "sketchStateSchema": "provider-keyed-v2",
               "postCoreSketchContinuationEligible": False,
               "pendingSketchChainIds": [chain.chain_id for chain in pending],
               "pendingSketchChainFingerprints": fingerprints},
        artifact_refs=[], created_at=claim_at, started_at=claim_at,
        finished_at=claim_at, events=[JobEvent(1, "info", "core deployed", {})],
    ))
    events = [
        JobEvent(1, "info", "provider host identity binding intended", manifest),
        JobEvent(2, "info", "provider bootstrap completed; strict host proof pending", {
            "manifestSha256": digest, "chainIds": [chain.chain_id for chain in pending],
            "hostProofPending": True,
        }),
    ]
    parent = jobs.save(StoredJobRun(
        id="job-provider-keyed-initial-core", action="provider_keyed_initial",
        status="running", target=f"engagement:{reviewed.engagement_id}",
        target_type="engagement", target_id=reviewed.engagement_id,
        requested_by="operator", artifact_refs=[],
        input={"engagementId": reviewed.engagement_id, "coreJobId": core_id,
               "corePlanId": plan_id, "planJobId": "job-provider-keyed-initial-plan-core",
               "applyJobId": "job-provider-keyed-initial-apply-core",
               "phase": "awaiting_strict_host_proof", "mutation": True,
               "claimOwner": "host-proof-worker", "claimToken": "token-a",
               "claimClaimedAt": claim_at, "claimExpiresAt": expiry},
        created_at=claim_at, started_at=claim_at, finished_at=None, events=events,
    ))
    assert leases.acquire(reviewed.engagement_id, plan_id, "provider_keyed_initial")
    node_rows = [row for item in projections for row in item.chain.nodes]
    proof = StrictHostSetProof(
        tuple(sorted(row["hostname"] for row in node_rows)),
        tuple(next(row["providerInstanceId"] for row in node_rows if row["hostname"] == name)
              for name in sorted(row["hostname"] for row in node_rows)),
        "e" * 64,
    )
    child_events = [JobEvent(1, "info", "strict host proof reserved", {"manifestSha256": digest}),
                    JobEvent(2, "info", "strict host proof started", {"manifestSha256": digest})]
    for row in node_rows:
        fields = {"hostname": row["hostname"], "terraformAddress": row["terraformAddress"],
                  "providerInstanceId": row["providerInstanceId"]}
        scratch = workspace + "/.proof-" + row["hostname"]
        child_events.append(JobEvent(len(child_events) + 1, "info",
            "strict host proof scratch intended", {**fields, "scratchPath": scratch}))
        for number in range(4):
            invocation = row["hostname"] + f"-{number}"
            child_events.extend([
                JobEvent(len(child_events) + 1, "info", "strict host proof command intended",
                         {**fields, "invocationId": invocation, "scratchPath": scratch,
                          "argvSha256": "a" * 64}),
                JobEvent(len(child_events) + 2, "info", "strict host proof command started before GO",
                         {**fields, "invocationId": invocation, "bootId": "boot",
                          "pid": 1, "pgid": 1, "startTicks": 1}),
                JobEvent(len(child_events) + 3, "info", "strict host proof command result fenced",
                         {**fields, "invocationId": invocation, "returnCode": 0,
                          "stdoutBytes": 1, "stderrBytes": 0,
                          "stdoutTruncated": False, "stderrTruncated": False}),
            ])
        child_events.append(JobEvent(len(child_events) + 1, "info",
            "strict host proof capture completed", fields))
    child_events.append(JobEvent(len(child_events) + 1, "info", "strict host proof completed", {
        "hostEvidenceSha256": "e" * 64, "hostnames": list(proof.hostnames)}))
    proof_child = jobs.save(StoredJobRun(
        id="job-provider-keyed-initial-host-proof-core",
        action="provider_keyed_initial_host_proof", status="running",
        target=f"engagement:{reviewed.engagement_id}", target_type="engagement",
        target_id=reviewed.engagement_id, requested_by="operator", artifact_refs=[],
        input={"engagementId": reviewed.engagement_id, "coreJobId": core_id,
               "corePlanId": plan_id, "parentJobId": parent.id,
               "manifestSha256": digest, "mutation": False,
               "claimOwner": "host-proof-worker", "claimToken": "token-a",
               "claimClaimedAt": claim_at, "claimExpiresAt": expiry},
        created_at=claim_at, started_at=claim_at, finished_at=None,
        events=child_events,
    ))
    args = dict(
        parent=parent, pending_chains=pending, projected_chains=projections,
        host_proof=proof, host_evidence_sha256="e" * 64,
        state_sha256=attachment.state_sha256, manifest=manifest,
        manifest_sha256=digest, applied_workspace_path=workspace,
        expected_event_digest=job_event_digest(parent.events),
        proof_child=proof_child, proof_child_event_digest=job_event_digest(proof_child.events),
        claim_owner="host-proof-worker", claim_token="token-a", finished_at=finish_at,
    )
    return repo, jobs, leases, args


def test_old_structured_evidence_cannot_publish(client):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        old = HostEvidenceValidation(args["host_proof"].hostnames,
                                     args["host_proof"].provider_instance_ids)
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**{**args, "host_proof": old})
        assert jobs.get(args["parent"].id).status == "running"


def test_child_journal_drift_rolls_back_parent_chains_and_lease(client):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        db.session.execute(text("""
            UPDATE job_events SET message = 'changed'
            WHERE job_id = :child AND sequence = 2
        """), {"child": args["proof_child"].id})
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"
        assert jobs.get(args["proof_child"].id).status == "running"
        assert all(row.status == "pending" for row in
                   repo.list_for_engagement(args["parent"].target_id))


def test_partial_second_host_command_journal_cannot_publish(client):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        child = args["proof_child"]
        second = args["host_proof"].hostnames[1]
        events = [event for event in child.events if not (
            event.message == "strict host proof command result fenced"
            and event.data.get("hostname") == second)]
        events = [replace(event, sequence=index) for index, event in enumerate(events, 1)]
        proposal = {**args, "proof_child": replace(child, events=events),
                    "proof_child_event_digest": job_event_digest(events)}
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**proposal)
        assert jobs.get(args["parent"].id).status == "running"
        assert all(row.status == "pending" for row in
                   repo.list_for_engagement(args["parent"].target_id))


def test_child_claim_drift_rolls_back_parent_cas(client):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        db.session.execute(text("""
            UPDATE job_runs SET input = json_set(input, '$.claimToken', 'changed')
            WHERE id = :child
        """), {"child": args["proof_child"].id})
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"
        assert all(row.status == "pending" for row in
                   repo.list_for_engagement(args["parent"].target_id))


def test_child_command_append_preserves_existing_journal_on_drift(client):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        child = args["proof_child"]
        # Simulate the penultimate command boundary before the proof result.
        prior = jobs.save(replace(child, events=child.events[:-1]))
        event = child.events[-1]
        appended = repo.append_provider_keyed_host_proof_event(
            prior, event, owner="host-proof-worker", token="token-a",
            started_at=prior.started_at)
        assert appended is not None and appended.events[-1] == event
        stale = replace(prior, events=prior.events[:-1])
        attempted = repo.append_provider_keyed_host_proof_event(
            stale, JobEvent(len(stale.events) + 1, "info", "unexpected", {}),
            owner="host-proof-worker", token="token-a", started_at=stale.started_at)
        assert attempted is None
        assert jobs.get(child.id).events[-1] == event


def test_publishes_both_chains_and_parent_with_one_exact_lease_release(client):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        rows = repo.publish_provider_keyed_initial_chains(**args)
        assert len(rows) == 2 and all(row.status == "deployed" for row in rows)
        assert all(row.deploy_job_id == args["parent"].id for row in rows)
        assert all(row.terraform_working_directory == args["applied_workspace_path"] for row in rows)
        assert all(node["status"] == "deployed" for row in rows for node in row.nodes)
        terminal = jobs.get(args["parent"].id)
        assert terminal.status == "succeeded" and terminal.input["phase"] == "completed"
        assert "claimToken" not in terminal.input
        assert terminal.events[-1].data["hostEvidenceSha256"] == "e" * 64
        assert leases.acquire(rows[0].engagement_id, "next-owner", "prepare")
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)


def test_corrected_initial_plan_preserves_inert_aborted_prior_row(client):
    with client.application.storage_context():
        repo, jobs, _leases, args = _case(client)
        original = args["pending_chains"][0]
        ghost = repo.save(replace(original, chain_id="proxy01-nyc3-01", status="aborted"))
        rows = repo.publish_provider_keyed_initial_chains(**args)
        assert len(rows) == 2 and all(row.status == "deployed" for row in rows)
        assert repo.get(ghost.engagement_id, ghost.chain_id) == ghost
        assert jobs.get(args["parent"].id).status == "succeeded"


def test_prior_row_with_durable_node_blocks_atomic_publication(client):
    with client.application.storage_context():
        repo, jobs, _leases, args = _case(client)
        original = args["pending_chains"][0]
        repo.save(replace(original, chain_id="proxy01-nyc3-01", status="aborted",
                          nodes=[{"providerInstanceId": "retained"}]))
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"


def test_settled_attachment_parent_optional_fields_are_accepted(client):
    with client.application.storage_context():
        repo, jobs, _leases, args = _case(client)
        parent = jobs.save(replace(args["parent"], input={
            **args["parent"].input,
            "nextAttachmentCheckAt": args["parent"].input["claimClaimedAt"],
            "attachmentRecheckCount": 2,
        }))
        args["parent"] = parent
        args["expected_event_digest"] = job_event_digest(parent.events)
        assert len(repo.publish_provider_keyed_initial_chains(**args)) == 2
        finished = jobs.get(parent.id)
        assert finished.input["attachmentRecheckCount"] == 2


def test_sibling_write_failure_rolls_back_parent_and_first_chain(client):
    with client.application.storage_context():
        repo, jobs, _leases, args = _case(client)
        sibling_id = args["pending_chains"][1].chain_id
        assert sibling_id == "proxy02-sfo-01"
        db.session.execute(text("""
            CREATE TRIGGER block_second_chain BEFORE UPDATE ON sketch_chains
            WHEN NEW.chain_id = 'proxy02-sfo-01'
            BEGIN SELECT RAISE(ABORT, 'injected write failure'); END
        """))
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"
        assert all(row.status == "pending" and not row.nodes for row in
                   repo.list_for_engagement(args["parent"].target_id))


def test_expired_claim_cannot_publish_with_backdated_finished_at(client):
    with client.application.storage_context():
        repo, jobs, _leases, args = _case(client)
        old_expiry = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        parent = jobs.save(replace(args["parent"], input={
            **args["parent"].input, "claimExpiresAt": old_expiry,
        }))
        args["parent"] = parent
        args["finished_at"] = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(parent.id).status == "running"
        assert all(row.status == "pending" for row in repo.list_for_engagement(parent.target_id))


def test_changed_core_generation_blocks_publication(client):
    from app.storage.models import JobRunModel

    with client.application.storage_context():
        repo, jobs, _leases, args = _case(client)
        core = JobRunModel.query.filter_by(id="job-core").one()
        core.requested_by = "other-operator"
        db.session.commit()
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"
        assert all(row.status == "pending" for row in
                   repo.list_for_engagement(args["parent"].target_id))


@pytest.mark.parametrize("drift", ["claim", "journal", "sibling", "lease", "proof", "workspace", "digest"])
def test_any_drift_rolls_back_all_three_rows_and_retains_lease(client, drift):
    with client.application.storage_context():
        repo, jobs, leases, args = _case(client)
        if drift == "claim":
            args["claim_token"] = "stale-token"
        elif drift == "journal":
            row = JobEventModel.query.filter_by(job_id=args["parent"].id, sequence=1).one()
            row.message = "rewritten with same count"
            db.session.commit()
        elif drift == "sibling":
            sibling = args["pending_chains"][1]
            repo.save(replace(sibling, burned_note="changed"))
        elif drift == "lease":
            leases.retag_if_operation(args["parent"].target_id, "plan-core",
                                      "provider_keyed_initial", "provider_keyed_teardown_fence")
        elif drift == "proof":
            args["host_proof"] = replace(args["host_proof"], provider_instance_ids=("999",))
        elif drift == "workspace":
            args["applied_workspace_path"] = "/private/tmp/other"
        else:
            args["host_evidence_sha256"] = "not-a-digest"
        with pytest.raises(ProviderKeyedPublicationConflict):
            repo.publish_provider_keyed_initial_chains(**args)
        assert jobs.get(args["parent"].id).status == "running"
        assert all(row.status == "pending" and not row.nodes for row in
                   repo.list_for_engagement(args["parent"].target_id))
        from app.storage.models import CoreMutationLeaseModel
        lease = CoreMutationLeaseModel.query.filter_by(engagement_id=args["parent"].target_id).one()
        assert lease.owner_id == "plan-core"
        assert lease.operation == ("provider_keyed_teardown_fence" if drift == "lease"
                                   else "provider_keyed_initial")
