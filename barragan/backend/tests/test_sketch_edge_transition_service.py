# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app import create_app
from app.core.config import TestConfig
from app.domain import JobEvent
from app.services.sketch_chains import (
    SketchChainValidationError,
    replace_sketch_chain_final_edge,
    retire_sketch_chain_final_edge,
)
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


@pytest.fixture(autouse=True)
def _existing_split_engagement(monkeypatch):
    monkeypatch.setattr(
        "app.services.sketch_chains.get_engagement",
        lambda identifier: SimpleNamespace(sketch_state_schema="split-v1")
        if identifier == "eng-edge-transition" else None,
    )


@pytest.mark.parametrize("operation", [retire_sketch_chain_final_edge, replace_sketch_chain_final_edge])
@pytest.mark.parametrize("engagement", [None, SimpleNamespace(sketch_state_schema="provider-keyed-v2")])
def test_legacy_edge_transition_rejects_missing_or_keyed_engagement(monkeypatch, operation, engagement):
    monkeypatch.setattr("app.services.sketch_chains.get_engagement", lambda _: engagement)
    mutation_check = Mock()
    monkeypatch.setattr("app.services.sketch_chains._assert_core_mutation_allowed", mutation_check)
    chains, jobs = Mock(), Mock()
    with pytest.raises(SketchChainValidationError) as error:
        operation("eng-edge-transition", "proxy01-sea-01", {}, repository=chains, job_repository=jobs)
    assert error.value.errors == ["chain-scoped deployment requires an existing split-v1 engagement"]
    mutation_check.assert_not_called()
    assert not chains.mock_calls and not jobs.mock_calls


class _ChainRepository:
    def __init__(self, chain: StoredSketchChain):
        self.chain = chain

    def get(self, engagement_id: str, chain_id: str) -> StoredSketchChain | None:
        if (engagement_id, chain_id) == (self.chain.engagement_id, self.chain.chain_id):
            return self.chain
        return None

    def save(self, chain: StoredSketchChain) -> StoredSketchChain:
        self.chain = chain
        return chain


def test_retire_final_edge_reconciles_only_final_count_index_and_retains_middle(tmp_path, monkeypatch):
    app = create_app(TestConfig)
    chain = _chain()
    chain_repo = _ChainRepository(chain)
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite3")
    removed: list[str] = []

    monkeypatch.setattr("app.services.sketch_chains._edge_transition_operations_overview", lambda _engagement_id: {"inboundChannels": []})
    monkeypatch.setattr("app.services.sketch_chains.is_provider_region_allowed", lambda _provider, _region: True)
    monkeypatch.setattr(
        "app.services.sketch_chains._remove_outbound_channel_for_teardown",
        lambda _engagement_id, chain_id, **_kwargs: removed.append(chain_id),
    )
    monkeypatch.setattr(
        "app.services.sketch_chains._start_same_provider_edge_reconcile",
        lambda chain, body, repository: _save_reconcile_job(repository, chain, body),
    )

    with app.storage_context():
        result = retire_sketch_chain_final_edge(
            chain.engagement_id,
            chain.chain_id,
            {"edgeId": "edge-02", "confirmation": f"retire-edge-{chain.chain_id}-edge-02"},
            repository=chain_repo,
            job_repository=jobs,
        )

    assert removed == [chain.chain_id]
    assert result["job"]["status"] == "succeeded"
    assert chain_repo.chain.status == "deployed"
    assert [edge["id"] for edge in chain_repo.chain.edge_intents or []] == ["edge-01"]
    assert [node["role"] for node in chain_repo.chain.nodes] == ["middle", "edge"]
    reconcile = next(job for job in jobs.list() if job.action == "linode_sketch_reconcile")
    assert reconcile.input["expectedEdgeAddress"] == "linode_instance.edge[1]"
    assert reconcile.input["expectedEdgeAction"] == "delete"


def test_replace_final_edge_adds_new_region_to_retained_middle_and_bootstraps(tmp_path, monkeypatch):
    app = create_app(TestConfig)
    chain = replace(_chain(), edge_count=1, edge_intents=[_edges()[0]], nodes=_nodes("us-sea"))
    chain_repo = _ChainRepository(chain)
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite3")
    bootstrapped: list[str] = []

    # The retained edge remains routable while its replacement is added.  Its
    # healthy outbound profile must not block the count-safe append operation.
    monkeypatch.setattr(
        "app.services.sketch_chains._edge_transition_operations_overview",
        lambda _engagement_id: {
            "inboundChannels": [],
            "outboundChannels": [{"chainId": chain.chain_id, "status": "Validated"}],
        },
    )
    monkeypatch.setattr("app.services.sketch_chains.is_provider_region_allowed", lambda _provider, _region: True)
    monkeypatch.setattr(
        "app.services.sketch_chains._start_same_provider_edge_reconcile",
        lambda chain, body, repository: _save_reconcile_job(repository, chain, body),
    )
    monkeypatch.setattr(
        "app.services.sketch_chains._bootstrap_provider_job",
        lambda _engagement_id, chain_id, _chain_repository, _jobs: bootstrapped.append(chain_id),
    )

    def refresh(_engagement_id, _chain_id, *, repository, **_kwargs):
        repository.save(replace(repository.chain, status="deployed"))
        return {"sketchChain": repository.chain.to_dict()}

    monkeypatch.setattr("app.services.sketch_chains.refresh_sketch_chain_from_job", refresh)

    with app.storage_context():
        result = replace_sketch_chain_final_edge(
            chain.engagement_id,
            chain.chain_id,
            {"region": "us-dal", "confirmation": f"replace-edge-{chain.chain_id}-us-dal"},
            repository=chain_repo,
            job_repository=jobs,
        )

    assert result["job"]["status"] == "succeeded"
    assert bootstrapped == [chain.chain_id]
    assert chain_repo.chain.status == "deployed"
    assert [(edge["id"], edge["region"]) for edge in chain_repo.chain.edge_intents or []] == [
        ("edge-01", "us-sea"),
        ("edge-02", "us-dal"),
    ]
    reconcile = next(job for job in jobs.list() if job.action == "linode_sketch_reconcile")
    assert reconcile.input["expectedEdgeAddress"] == "linode_instance.edge[1]"
    assert reconcile.input["expectedEdgeAction"] == "create"


def test_retire_rejects_transition_that_would_break_upstream_equal_region_counts(tmp_path, monkeypatch):
    app = create_app(TestConfig)
    edges = [
        {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
        {"id": "edge-02", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
        {"id": "edge-03", "provider": "linode", "region": "us-dal", "size": "g6-nanode-1"},
        {"id": "edge-04", "provider": "linode", "region": "us-dal", "size": "g6-nanode-1"},
    ]
    chain_repo = _ChainRepository(replace(_chain(), edge_count=4, edge_intents=edges))
    monkeypatch.setattr("app.services.sketch_chains._edge_transition_operations_overview", lambda _engagement_id: {"inboundChannels": []})
    monkeypatch.setattr("app.services.sketch_chains.is_provider_region_allowed", lambda _provider, _region: True)

    with app.storage_context():
        try:
            retire_sketch_chain_final_edge(
                chain_repo.chain.engagement_id,
                chain_repo.chain.chain_id,
                {"edgeId": "edge-04", "confirmation": f"retire-edge-{chain_repo.chain.chain_id}-edge-04"},
                repository=chain_repo,
                job_repository=SqliteJobRepository(tmp_path / "jobs.sqlite3"),
            )
        except SketchChainValidationError as exc:
            assert exc.errors == [
                "edge regions have unequal counts (us-sea=2, us-dal=1); the retained Terraform state requires the same edge count in every selected region"
            ]
        else:
            raise AssertionError("an unequal upstream edge-region count was accepted")


def test_retire_rejects_mixed_provider_chain_before_removing_the_final_edge(tmp_path, monkeypatch):
    app = create_app(TestConfig)
    edges = [
        {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
        {"id": "edge-02", "provider": "digitalocean", "region": "sfo3", "size": "s-1vcpu-1gb"},
    ]
    chain_repo = _ChainRepository(replace(_chain(), edge_count=2, edge_intents=edges))
    monkeypatch.setattr("app.services.sketch_chains._edge_transition_operations_overview", lambda _engagement_id: {"inboundChannels": []})

    with app.storage_context():
        try:
            retire_sketch_chain_final_edge(
                chain_repo.chain.engagement_id,
                chain_repo.chain.chain_id,
                {"edgeId": "edge-02", "confirmation": f"retire-edge-{chain_repo.chain.chain_id}-edge-02"},
                repository=chain_repo,
                job_repository=SqliteJobRepository(tmp_path / "jobs.sqlite3"),
            )
        except SketchChainValidationError as exc:
            assert exc.errors == ["retained-middle edge transitions require every edge to use the middle provider"]
        else:
            raise AssertionError("a mixed-provider chain was accepted for retained-state edge mutation")


def _save_reconcile_job(repository, chain: StoredSketchChain, body: dict) -> StoredJobRun:
    region = next(edge["region"] for edge in body["edges"] if edge["id"] == body["edges"][-1]["id"])
    job = StoredJobRun(
        id="job-provider-reconcile",
        action="linode_sketch_reconcile",
        status="succeeded",
        target=f"engagement:{chain.engagement_id}",
        target_type="engagement",
        target_id=chain.engagement_id,
        requested_by="operator",
        input={"terraformWorkingDirectory": chain.terraform_working_directory, **body},
        artifact_refs=[],
        created_at="2026-09-01T00:00:00+00:00",
        started_at="2026-09-01T00:00:00+00:00",
        finished_at="2026-09-01T00:00:01+00:00",
        events=[JobEvent(1, "info", "Terraform output recorded", {"sketchInfrastructure": _nodes(region)})],
    )
    return repository.save(job)


def _chain() -> StoredSketchChain:
    return StoredSketchChain(
        chain_id="proxy01-sea-01",
        engagement_id="eng-edge-transition",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        edge_count=2,
        edge_intents=_edges(),
        status="deployed",
        burned=False,
        burned_note="",
        deploy_job_id="job-deploy",
        teardown_job_id="",
        terraform_working_directory="/tmp/barragan/sketch-state",
        nodes=_nodes("us-central"),
        created_at="2026-09-01T00:00:00+00:00",
        updated_at="2026-09-01T00:00:00+00:00",
    )


def _edges() -> list[dict[str, str]]:
    return [
        {"id": "edge-01", "provider": "linode", "region": "us-sea", "size": "g6-nanode-1"},
        {"id": "edge-02", "provider": "linode", "region": "us-central", "size": "g6-nanode-1"},
    ]


def _nodes(edge_region: str) -> list[dict[str, str]]:
    return [
        {"hostname": "middle-retained", "role": "middle", "provider": "linode", "region": "us-sea", "publicIp": "203.0.113.10"},
        {"hostname": f"edge-{edge_region}", "role": "edge", "provider": "linode", "region": edge_region, "publicIp": "203.0.113.20"},
    ]
