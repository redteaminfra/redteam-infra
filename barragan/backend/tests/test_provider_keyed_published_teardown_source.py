# Copyright (c) 2026, Oracle and/or its affiliates.
"""No-network audit of a completed, persisted two-chain keyed generation."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_chain_projection import project_digitalocean_initial_chains
from app.services.provider_keyed_published_teardown_source import (
    PublishedProviderKeyedSourceError, audit_published_provider_keyed_source,
)
from app.storage.sketch_chain_repository import StoredSketchChain
from test_provider_keyed_chain_projection import _fixture as projection_fixture
from test_provider_keyed_teardown_quiescence import _completed


class _Chains:
    def __init__(self, rows):
        self.rows = rows

    def list_for_engagement(self, engagement_id):
        return [row for row in self.rows if row.engagement_id == engagement_id]


def _case(tmp_path):
    jobs, parent, root, scope = _completed(tmp_path)
    manifest = next(event.data for event in parent.events
                    if event.message == "provider host identity binding intended")
    reviewed, attachment, proof, chains = projection_fixture()
    projected = project_digitalocean_initial_chains(reviewed, attachment, proof, chains)
    rows = [replace(item.chain, status="deployed", deploy_job_id=parent.id,
                    terraform_working_directory=str(root),
                    nodes=[{**node, "status": "deployed"} for node in item.chain.nodes])
            for item in projected]
    names = sorted(node["hostname"] for row in rows for node in row.nodes)
    by_name = {node["hostname"]: node["providerInstanceId"] for row in rows for node in row.nodes}
    terminal = JobEvent(len(parent.events) + 1, "info", "provider two-chain host proof published", {
        "hostEvidenceSha256": "e" * 64, "stateSha256": scope["stateSha256"],
        "manifestSha256": parent.events[-1].data["manifestSha256"],
        "chainIds": scope["chainIds"], "hostnames": names,
        "providerInstanceIds": [by_name[name] for name in names],
    })
    finished = replace(parent, status="succeeded", finished_at=parent.started_at,
                       input={**{key: value for key, value in parent.input.items()
                                 if not key.startswith("claim")}, "phase": "completed"},
                       events=[*parent.events, terminal])
    jobs.save(finished)
    core = jobs.get(scope["coreJobId"])
    core = jobs.save(replace(core, finished_at=parent.started_at))
    plan = SimpleNamespace(id=scope["corePlanId"], engagement_id=core.input["engagementId"],
                           status="applied", apply_job_id=core.id,
                           evidence={"sketchStateSchema": "provider-keyed-v2",
                                     "pendingSketchChainIds": scope["chainIds"],
                                     "pendingSketchChainFingerprints": scope["chainFingerprints"]})
    scope = {**scope, "provider": "digitalocean", "revisionId": manifest["revisionId"], "resources": [
        {"address": node["terraformAddress"], "id": str(node["providerInstanceId"]),
         "kind": "droplet"} for node in manifest["nodes"]
    ]}
    state = {"scope": scope, "lease": None, "plan": plan}
    options = dict(environment="devtest", state_root=tmp_path / "state", job_repository=jobs,
                   plan_repository=SimpleNamespace(get=lambda _id: state["plan"]),
                   sketch_repository=_Chains(rows),
                   lease_lookup=lambda _engagement: state["lease"],
                   scope_builder=lambda *_args, **_kwargs: state["scope"])
    return jobs, finished, manifest, rows, state, options


def _audit(options):
    return audit_published_provider_keyed_source("job-core", **options)


def test_persisted_published_source_is_sealed_and_restart_readable(tmp_path):
    jobs, parent, _manifest, _rows, _state, options = _case(tmp_path)
    proof = _audit(options)
    assert proof.initial_job_id == parent.id
    assert proof.published_host_evidence_sha256 == "e" * 64
    assert len(proof.chain_ids) == 2
    # New repository instance reads the same persisted SQLite job journal.
    from app.storage.job_repository import SqliteJobRepository
    options["job_repository"] = SqliteJobRepository(tmp_path / "jobs.sqlite")
    assert _audit(options) == proof


@pytest.mark.parametrize("reverse", [False, True])
def test_published_source_ignores_only_strict_inert_aborted_history(tmp_path, reverse):
    _jobs, _parent, _manifest, rows, _state, options = _case(tmp_path)
    proof = _audit(options)
    ghost = replace(rows[0], chain_id="aborted-history", status="aborted", nodes=[],
                    deploy_job_id="", teardown_job_id="", terraform_working_directory="", burned=False)
    complete = [ghost, *rows]
    if reverse:
        complete.reverse()
    options["sketch_repository"] = _Chains(complete)
    assert _audit(options) == proof


@pytest.mark.parametrize("drift", ["nodes", "deploy", "teardown", "workspace", "burned", "pending", "foreign", "duplicate"])
def test_published_source_extra_chain_needs_exact_inert_identity(tmp_path, drift):
    _jobs, _parent, _manifest, rows, _state, options = _case(tmp_path)
    ghost = replace(rows[0], chain_id="aborted-history", status="aborted", nodes=[],
                    deploy_job_id="", teardown_job_id="", terraform_working_directory="", burned=False)
    changes = {"nodes": {"nodes": rows[0].nodes}, "deploy": {"deploy_job_id": "job-unknown"},
               "teardown": {"teardown_job_id": "job-unknown"}, "workspace": {"terraform_working_directory": "/tmp/other"},
               "burned": {"burned": True}, "pending": {"status": "pending"},
               "foreign": {"engagement_id": "foreign"}, "duplicate": {"chain_id": rows[0].chain_id}}
    ghost = replace(ghost, **changes[drift])
    from types import SimpleNamespace
    options["sketch_repository"] = SimpleNamespace(list_for_engagement=lambda _: [*rows, ghost])
    with pytest.raises(PublishedProviderKeyedSourceError):
        _audit(options)


def test_append_plan_reaudit_requires_exact_lease_and_parent(tmp_path):
    _jobs, _parent, _manifest, _rows, state, options = _case(tmp_path)
    expected = _audit(options)
    state["lease"] = (expected.core_plan_id, "provider_keyed_edge_append")
    with pytest.raises(PublishedProviderKeyedSourceError):
        _audit(options)
    observed = []
    options["scope_builder"] = lambda *_args, **kwargs: (
        observed.append(kwargs.get("allowed_append_plan_parent_id")) or state["scope"])
    options["expected_mutation_lease"] = state["lease"]
    options["allowed_append_plan_parent_id"] = "job-append"
    assert _audit(options) == expected
    assert observed == ["job-append", "job-append"]
    state["lease"] = (expected.core_plan_id, "provider_keyed_teardown_fence")
    with pytest.raises(PublishedProviderKeyedSourceError):
        _audit(options)


@pytest.mark.parametrize("tamper", [
    "short_journal", "duplicate_terminal", "host_digest", "row_node", "row_status",
    "row_job", "lease", "state", "plan", "manifest",
])
def test_published_source_fails_closed_on_persisted_drift(tmp_path, tamper):
    jobs, parent, manifest, rows, state, options = _case(tmp_path)
    if tamper == "short_journal":
        jobs.save(replace(parent, events=[parent.events[0],
            replace(parent.events[-1], sequence=2)]))
    elif tamper == "duplicate_terminal":
        jobs.save(replace(parent, events=[*parent.events,
            replace(parent.events[-1], sequence=len(parent.events) + 1)]))
    elif tamper == "host_digest":
        jobs.save(replace(parent, events=[*parent.events[:-1],
            replace(parent.events[-1], data={**parent.events[-1].data,
                "hostEvidenceSha256": "bad"})]))
    elif tamper == "row_node":
        rows[0] = replace(rows[0], nodes=[{**rows[0].nodes[0], "providerInstanceId": "999"},
                                          *rows[0].nodes[1:]])
    elif tamper == "row_status":
        rows[0] = replace(rows[0], status="pending")
    elif tamper == "row_job":
        rows[0] = replace(rows[0], deploy_job_id="other")
    elif tamper == "lease":
        state["lease"] = ("plan-core", "provider_keyed_initial")
    elif tamper == "state":
        state["scope"] = {**state["scope"], "stateSha256": "f" * 64}
    elif tamper == "plan":
        state["plan"] = replace(state["plan"], status="draft") if hasattr(
            state["plan"], "__dataclass_fields__") else SimpleNamespace(
                **{**vars(state["plan"]), "status": "draft"})
    elif tamper == "manifest":
        intended = next(index for index, event in enumerate(parent.events)
                        if event.message == "provider host identity binding intended")
        events = list(parent.events)
        events[intended] = replace(events[intended], data={**manifest, "stateSha256": "f" * 64})
        jobs.save(replace(parent, events=events))
    with pytest.raises(PublishedProviderKeyedSourceError):
        _audit(options)


def test_source_change_between_independent_reads_fails(tmp_path):
    _jobs, _parent, _manifest, _rows, state, options = _case(tmp_path)
    calls = 0
    def moving_scope(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            return {**state["scope"], "revisionId": "changed"}
        return state["scope"]
    options["scope_builder"] = moving_scope
    with pytest.raises(PublishedProviderKeyedSourceError):
        _audit(options)


def test_published_source_accepts_pruned_empty_scratch_after_restart(tmp_path):
    _jobs, parent, _manifest, _rows, _state, options = _case(tmp_path)
    prepared = next(event for event in parent.events
                    if event.message == "provider bootstrap preparation fenced")
    for raw in prepared.data["scratchPaths"]:
        Path(raw).rmdir()
    assert _audit(options).initial_job_id == parent.id
