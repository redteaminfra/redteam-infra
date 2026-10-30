# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted publication -> published teardown-source audit, without providers."""

from dataclasses import replace

from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_published_teardown_source import audit_published_provider_keyed_source
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_chain_publication import _case as publication_case
from test_provider_keyed_teardown_quiescence import _completed


def test_real_sql_publication_then_persisted_reread_audits_complete_initial_journal(client, tmp_path):
    # `_completed` executes the full gated two-chain bootstrap with audited
    # command start/results and leaves its real scratch paths on disk.
    _bootstrap_jobs, bootstrap_parent, workspace, _bootstrap_scope = _completed(tmp_path)
    manifest = next(event.data for event in bootstrap_parent.events
                    if event.message == "provider host identity binding intended")
    with client.application.storage_context():
        chains, jobs, _leases, args = publication_case(client, workspace_path=str(workspace))
        pending = jobs.save(replace(args["parent"], events=bootstrap_parent.events))
        manifest_sha256 = _digest_json(manifest)
        proof_child = args["proof_child"]
        proof_child = jobs.save(replace(
            proof_child,
            input={**proof_child.input, "manifestSha256": manifest_sha256},
            events=[replace(event, data={"manifestSha256": manifest_sha256})
                    if event.message in {"strict host proof reserved", "strict host proof started"}
                    else event for event in proof_child.events],
        ))
        args.update(
            parent=pending,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            state_sha256=manifest["stateSha256"],
            applied_workspace_path=str(workspace),
            expected_event_digest=job_event_digest(pending.events),
            proof_child=proof_child,
            proof_child_event_digest=job_event_digest(proof_child.events),
        )
        published = chains.publish_provider_keyed_initial_chains(**args)
        assert len(published) == 2 and all(row.status == "deployed" for row in published)

        # New repository objects reread the persisted SQL rows in this same
        # storage context; this is not an application/process restart. The
        # injected provider scope omits non-Droplet resources and does not
        # prove complete Terraform state. The production scope builder has
        # separate tests.
        reopened_jobs = SqlAlchemyJobRepository()
        reopened_plans = SqlAlchemyDeploymentPlanRepository()
        reopened_chains = SqlAlchemySketchChainRepository()
        core = reopened_jobs.get("job-core")
        scope = {
            "schema": "provider-keyed-v2", "provider": "digitalocean",
            "coreJobId": core.id, "corePlanId": core.input["corePlanId"],
            "workspace": str(workspace), "stateSha256": manifest["stateSha256"],
            "sourceRevision": manifest["sourceRevision"],
            "providerConnectionId": manifest["providerConnectionId"],
            "revisionId": manifest["revisionId"],
            "chainIds": core.input["pendingSketchChainIds"],
            "chainFingerprints": core.input["pendingSketchChainFingerprints"],
            "resources": [
                {"address": node["terraformAddress"],
                 "id": str(node["providerInstanceId"]), "kind": "droplet"}
                for node in manifest["nodes"]
            ],
        }
        from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
        proof = audit_published_provider_keyed_source(
            core.id, job_repository=reopened_jobs, plan_repository=reopened_plans,
            sketch_repository=reopened_chains, lease_lookup=_db_lease_lookup,
            scope_builder=lambda *_args, **_kwargs: scope,
        )
        assert proof.initial_job_id == pending.id
        assert proof.initial_journal_sha256 == job_event_digest(reopened_jobs.get(pending.id).events)
        assert proof.chain_ids == tuple(core.input["pendingSketchChainIds"])
        assert proof.published_host_evidence_sha256 == args["host_evidence_sha256"]
