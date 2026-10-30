# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published mixed teardown has a distinct, read-only authority boundary."""

from dataclasses import asdict, replace
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_mixed_initial_apply_child import _child_id
from app.services.provider_keyed_mixed_initial_apply_child import recognize_mixed_initial_apply_terminal
from app.services.provider_keyed_mixed_initial_bootstrap import _worker_id
from app.services.provider_keyed_mixed_initial_host_binding import _binding_child_id, _digest
from app.services.provider_keyed_mixed_published_teardown_authority import (
    PublishedMixedInitialTeardownAttention,
    recheck_published_mixed_initial_teardown_go,
    review_published_mixed_initial_teardown,
)
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_teardown_scope import _published


def _case(ready, tmp_path):
    source, options, persisted = _published(ready, tmp_path)
    jobs = ready.case.jobs
    parent = jobs.get(source.parent_job_id)
    assert len(parent.events) == 7
    workspaces = {}
    for provider, chain_id in zip(source.ordered_providers, source.chain_ids, strict=True):
        terminal = recognize_mixed_initial_apply_terminal(
            jobs.get(_child_id(source.core_job_id, provider)), parent, provider)
        workspaces[provider] = Path(terminal["planPath"]).parent
        chain = persisted()[chain_id]
        SqlAlchemySketchChainRepository().save(replace(
            chain, terraform_working_directory=str(workspaces[provider])))
    evidence = "e" * 64
    source_sha = _digest(asdict(source))
    events = []
    def event(message, data):
        events.append(JobEvent(len(events) + 1, "info", message, data))
    event("mixed strict host proof reserved", {"sourceSha256": source_sha})
    event("mixed strict host proof started", {"sourceSha256": source_sha})
    for host in source.host_rows:
        fields = {"provider": host.provider, "hostname": host.hostname,
                  "terraformAddress": host.terraform_address,
                  "providerInstanceId": host.provider_instance_id}
        scratch = f"/tmp/{host.hostname}"
        event("mixed strict host scratch intended", {**fields, "scratchPath": scratch})
        for number in range(4):
            invocation = f"{host.hostname}-{number}"
            event("mixed strict host command intended", {**fields,
                "invocationId": invocation, "argvSha256": "a" * 64,
                "scratchPath": scratch})
            event("mixed strict host command started before GO", {**fields,
                "invocationId": invocation, "bootId": "boot", "pid": 10,
                "pgid": 10, "startTicks": 20})
            event("mixed strict host command result fenced", {**fields,
                "invocationId": invocation, "returnCode": 0,
                "stdoutBytes": 20, "stderrBytes": 0,
                "stdoutTruncated": False, "stderrTruncated": False})
        event("mixed strict host capture completed", {**fields,
            "collectionSha256": "b" * 64})
    completed = JobEvent(59, "info", "mixed strict host proof completed", {
        "sourceSha256": source_sha, "hostEvidenceSha256": evidence,
        "hostnames": [host.hostname for host in source.host_rows],
        "evidencePath": str(tmp_path / "raw-evidence.json"),
    })
    events += [completed, JobEvent(60, "info", "mixed strict host proof published", {
        "parentJobId": parent.id, "hostEvidenceSha256": evidence})]
    bootstrap = jobs.get(_worker_id(source.core_job_id))
    proof = jobs.save(replace(
        bootstrap, id="job-provider-keyed-mixed-strict-host-proof-core",
        action="provider_keyed_mixed_initial_strict_host_proof", events=events,
        input={
            "engagementId": source.engagement_id, "coreJobId": source.core_job_id,
            "corePlanId": source.core_plan_id, "mixedParentId": source.parent_job_id,
            "handoffJournalSha256": source.parent_journal_sha256,
            "bindingJobId": _binding_child_id(source.core_job_id),
            "bindingManifestSha256": source.binding_manifest_sha256,
            "bootstrapJobId": _worker_id(source.core_job_id),
            "bootstrapJournalSha256": source.host_worker_journal_sha256,
            "mutation": False,
        },
    ))
    parent = jobs.save(replace(
        parent, status="succeeded", finished_at=bootstrap.finished_at,
        input={**{key: value for key, value in parent.input.items()
                  if not key.startswith("claim")}, "phase": "completed"},
        events=[*parent.events, JobEvent(8, "info", "mixed two-provider host proof published", {
            "sourceSha256": _digest(asdict(source)),
            "hostEvidenceSha256": evidence,
            "chainIds": list(source.chain_ids),
            "providerStates": [{"provider": state.provider,
                                "stateSha256": state.state_sha256}
                               for state in source.provider_states],
        })]))
    args = dict(
        parent=parent, core=jobs.get(source.core_job_id),
        plan=replace(ready.case.records["core_plan"], stage="applied",
                     evidence={**ready.case.records["core_plan"].evidence,
                               "sketchStateSchema": "provider-keyed-v2"}),
        binding=jobs.get(_binding_child_id(source.core_job_id)),
        bootstrap=bootstrap, proof_child=proof,
        apply_children={provider: jobs.get(_child_id(source.core_job_id, provider))
                        for provider in source.ordered_providers},
        chains=persisted(), observations=options["observations"],
        workspaces=workspaces,
        live_bindings={key: () for key in ("channels", "domains", "certificates", "sites")},
        mutation_lease=None,
    )
    return source, args, persisted


def test_persisted_published_two_provider_review_and_fresh_go(client, ready, tmp_path):
    with client.application.storage_context():
        source, args, persisted = _case(ready, tmp_path)
        review = review_published_mixed_initial_teardown(**args)
        assert review.source == source
        assert tuple(scope["provider"] for scope in review.provider_scopes) == source.ordered_providers
        calls = []
        jobs = ready.case.jobs
        def reopened():
            calls.append("fresh")
            return review_published_mixed_initial_teardown(**{
                **args, "parent": jobs.get(source.parent_job_id),
                "proof_child": jobs.get(args["proof_child"].id),
                "binding": jobs.get(args["binding"].id),
                "bootstrap": jobs.get(args["bootstrap"].id),
                "apply_children": {provider: jobs.get(_child_id(source.core_job_id, provider))
                                   for provider in source.ordered_providers},
                "chains": persisted(),
                "mutation_lease": (source.core_plan_id, "provider_keyed_teardown_fence"),
                "allow_teardown_fence": True,
            })
        assert recheck_published_mixed_initial_teardown_go(
            review, fresh_review=reopened,
            fence=lambda: "unchanged-generation") == review
        assert calls == ["fresh"]


@pytest.mark.parametrize("drift", [
    "interrupted", "six_nodes", "binding", "lease", "parent_terminal",
    "proof_terminal", "proof_command", "state", "plan", "plan_review",
    "chain_intent",
    "workspace", "wrong_fence",
])
def test_published_source_rejects_drift_and_six_node_generation(client, ready, tmp_path, drift):
    with client.application.storage_context():
        source, args, persisted = _case(ready, tmp_path)
        if drift == "interrupted":
            args["parent"] = replace(args["parent"], status="running",
                                     finished_at=None,
                                     input={**args["parent"].input,
                                            "phase": "awaiting_mixed_host_proof"})
        elif drift == "six_nodes":
            chain = args["chains"][source.chain_ids[0]]
            changed = replace(chain, edge_count=2, nodes=[*chain.nodes, dict(chain.nodes[-1])])
            SqlAlchemySketchChainRepository().save(changed)
            args["chains"] = persisted()
        elif drift == "binding":
            args["live_bindings"]["domains"] = ("owned-domain",)
        elif drift == "lease":
            args["mutation_lease"] = (source.core_plan_id, "provider_keyed_initial")
        elif drift == "parent_terminal":
            parent = args["parent"]
            args["parent"] = replace(parent, events=[*parent.events[:-1], replace(
                parent.events[-1], data={**parent.events[-1].data,
                                         "sourceSha256": "0" * 64})])
        elif drift == "proof_terminal":
            proof = args["proof_child"]
            args["proof_child"] = replace(proof, events=[*proof.events[:-1], replace(
                proof.events[-1], data={"parentJobId": "other",
                                        "hostEvidenceSha256": "e" * 64})])
        elif drift == "proof_command":
            proof = args["proof_child"]
            events = list(proof.events)
            events[3] = replace(events[3], message="unproved command")
            args["proof_child"] = replace(proof, events=events)
        elif drift == "state":
            provider = source.ordered_providers[0]
            observed = args["observations"][provider]
            args["observations"] = {**args["observations"], provider: replace(
                observed, state_json=observed.state_json + b" ")}
        elif drift == "plan":
            args["plan"] = replace(args["plan"], status="draft")
        elif drift == "plan_review":
            plan = args["plan"]
            configuration = dict(plan.review["reviewedConfiguration"])
            configuration["sketchAuthorization"] = {
                **configuration["sketchAuthorization"], "fingerprint": "0" * 64}
            args["plan"] = replace(plan, review={**plan.review,
                "reviewedConfiguration": configuration})
        elif drift == "chain_intent":
            chain = args["chains"][source.chain_ids[0]]
            SqlAlchemySketchChainRepository().save(replace(chain, edge_region="other"))
            args["chains"] = persisted()
        elif drift == "wrong_fence":
            args["mutation_lease"] = (source.core_plan_id,
                                      "provider_keyed_teardown_fence")
        else:
            provider = source.ordered_providers[0]
            args["workspaces"] = {**args["workspaces"], provider: tmp_path / "other"}
        with pytest.raises(PublishedMixedInitialTeardownAttention):
            review_published_mixed_initial_teardown(**args)


def test_go_recheck_rejects_changed_fence_or_review(client, ready, tmp_path):
    with client.application.storage_context():
        _source, args, _persisted = _case(ready, tmp_path)
        review = review_published_mixed_initial_teardown(**args)
        generations = iter(("first", "second"))
        with pytest.raises(PublishedMixedInitialTeardownAttention):
            recheck_published_mixed_initial_teardown_go(
                review, fresh_review=lambda: review, fence=lambda: next(generations))
        with pytest.raises(PublishedMixedInitialTeardownAttention):
            recheck_published_mixed_initial_teardown_go(
                review, fresh_review=lambda: replace(review, live_binding_count=1),
                fence=lambda: "first")
