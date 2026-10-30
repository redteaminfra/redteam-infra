# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from app.domain import JobEvent
from app.services.sketch_chains import refresh_sketch_chain_from_job
from app.services.sketch_lifecycle_recovery import recover_sketch_lifecycle
from app.storage.job_repository import SqliteJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


class ChainRepository:
    def __init__(self, chain: StoredSketchChain):
        self.chain = chain
        self.save_count = 0

    def get(self, engagement_id: str, chain_id: str):
        if (engagement_id, chain_id) == (self.chain.engagement_id, self.chain.chain_id):
            return self.chain
        return None

    def save(self, chain: StoredSketchChain):
        self.chain = chain
        self.save_count += 1
        return chain

    def list_for_recovery(self, *, statuses=None, updated_before=None):
        if statuses is not None and self.chain.status not in statuses:
            return []
        if updated_before is not None and datetime.fromisoformat(self.chain.updated_at) > updated_before:
            return []
        return [self.chain]


def test_terminal_deploy_reconciliation_is_exact_and_idempotent(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    jobs.save(_job("job-deploy", "linode_sketch_deploy", "succeeded", topology=True))
    chains = ChainRepository(_chain(status="deploying", deploy_job_id="job-deploy"))
    continuations = []
    monkeypatch.setattr(
        "app.services.sketch_chains._start_outbound_auto_configuration",
        lambda *args, **kwargs: continuations.append((args, kwargs)),
    )

    first = refresh_sketch_chain_from_job("eng-1", "chain-1", repository=chains, job_repository=jobs)
    second = refresh_sketch_chain_from_job("eng-1", "chain-1", repository=chains, job_repository=jobs)

    assert first["sketchChain"]["status"] == "deployed"
    assert second["sketchChain"]["status"] == "deployed"
    assert chains.save_count == 1
    assert len(continuations) == 2


def test_startup_recovery_repairs_missed_terminal_deploy_callback(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    completed = _job("job-deploy", "linode_sketch_deploy", "succeeded", topology=True)
    jobs.save(replace(completed, events=completed.events[:1]))
    chains = ChainRepository(_chain(status="deploying", deploy_job_id="job-deploy"))
    monkeypatch.setattr("app.services.sketch_chains._start_outbound_auto_configuration", lambda *args, **kwargs: None)
    resumed = []
    monkeypatch.setattr(
        "app.services.sketch_lifecycle_recovery.resume_pending_sketch_bootstrap",
        lambda *args, **kwargs: resumed.append((args, kwargs)) or True,
    )

    outcomes = recover_sketch_lifecycle(
        startup=True,
        job_repository=jobs,
        sketch_repository=chains,
    )

    assert outcomes == [{"engagementId": "eng-1", "chainId": "chain-1", "jobId": "job-deploy", "state": "bootstrap_resumed"}]
    assert len(resumed) == 1
    assert chains.chain.status == "deploying"
    assert chains.chain.nodes[0]["hostname"] == "edge-1"


def test_startup_recovery_resumes_interrupted_bootstrap_without_reapplying_terraform(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    interrupted = _job("job-deploy", "linode_sketch_deploy", "running", topology=True)
    jobs.save(
        replace(
            interrupted,
            events=interrupted.events
            + [JobEvent(2, "info", "bootstrap started", {"bootstrap": "starting"})],
        )
    )
    chains = ChainRepository(_chain(status="deploying", deploy_job_id="job-deploy", nodes=[{"hostname": "edge-1"}]))
    resumed = []
    monkeypatch.setattr(
        "app.services.sketch_lifecycle_recovery.resume_pending_sketch_bootstrap",
        lambda *args, **kwargs: resumed.append((args, kwargs)) or True,
    )

    outcomes = recover_sketch_lifecycle(startup=True, job_repository=jobs, sketch_repository=chains)

    assert outcomes == [{"engagementId": "eng-1", "chainId": "chain-1", "jobId": "job-deploy", "state": "bootstrap_resumed"}]
    assert len(resumed) == 1


def test_startup_recovery_repairs_terminal_teardown_and_clears_nodes(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    jobs.save(_job("job-teardown", "linode_sketch_teardown", "succeeded"))
    chains = ChainRepository(
        _chain(status="tearing_down", deploy_job_id="job-deploy", teardown_job_id="job-teardown", nodes=[{"hostname": "edge-1"}])
    )

    recover_sketch_lifecycle(startup=True, job_repository=jobs, sketch_repository=chains)

    assert chains.chain.status == "destroyed"
    assert chains.chain.nodes == []


@pytest.mark.parametrize(
    ("action", "chain_status", "teardown_job_id"),
    [
        ("linode_sketch_deploy", "deploying", ""),
        ("digitalocean_sketch_deploy", "deploying", ""),
        ("mixed_provider_sketch_deploy", "deploying", ""),
        ("linode_sketch_teardown", "tearing_down", "job-terminal"),
        ("digitalocean_sketch_teardown", "tearing_down", "job-terminal"),
        ("mixed_provider_sketch_teardown", "tearing_down", "job-terminal"),
    ],
)
def test_startup_recovery_persists_provider_failures(
    tmp_path,
    monkeypatch,
    action,
    chain_status,
    teardown_job_id,
):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    jobs.save(_job("job-terminal", action, "failed"))
    chains = ChainRepository(
        _chain(
            status=chain_status,
            deploy_job_id="job-terminal",
            teardown_job_id=teardown_job_id,
            nodes=[{"hostname": "edge-1"}],
        )
    )
    monkeypatch.setattr("app.services.sketch_chains._start_outbound_auto_configuration", lambda *args, **kwargs: None)

    recover_sketch_lifecycle(startup=True, job_repository=jobs, sketch_repository=chains)

    assert chains.chain.status == "failed"
    assert chains.chain.nodes == [{"hostname": "edge-1"}]


def test_stale_running_provider_job_is_flagged_once_and_never_retried(tmp_path):
    class CountingJobs(SqliteJobRepository):
        def __init__(self, path):
            self.save_count = 0
            self.attention_count = 0
            super().__init__(path)

        def save(self, job):
            self.save_count += 1
            return super().save(job)

        def mark_stale_nonterminal_attention(self, *args, **kwargs):
            marked = super().mark_stale_nonterminal_attention(*args, **kwargs)
            self.attention_count += int(marked)
            return marked

    jobs = CountingJobs(tmp_path / "jobs.sqlite")
    jobs.save(_job("job-deploy", "linode_sketch_deploy", "running"))
    jobs.save_count = 0
    chains = ChainRepository(_chain(status="deploying", deploy_job_id="job-deploy"))
    now = datetime(2026, 8, 4, 1, 0, tzinfo=timezone.utc)

    first = recover_sketch_lifecycle(now=now, job_repository=jobs, sketch_repository=chains)
    second = recover_sketch_lifecycle(now=now, job_repository=jobs, sketch_repository=chains)

    assert first[0]["state"] == second[0]["state"] == "stale_attention"
    assert jobs.get("job-deploy").status == "running"
    assert jobs.get("job-deploy").input["lifecycleRecoveryAttention"] == "stale_nonterminal"
    assert jobs.save_count == 0
    assert jobs.attention_count == 1
    assert chains.save_count == 0


def test_provider_completion_wins_before_stale_attention_compare_and_swap(tmp_path):
    class CompletingJobs(SqliteJobRepository):
        def mark_stale_nonterminal_attention(self, job_id, *, expected_status, event):
            current = self.get(job_id)
            assert current is not None
            self.save(
                replace(
                    current,
                    status="succeeded",
                    finished_at="2026-08-04T00:59:59+00:00",
                    events=current.events
                    + [JobEvent(len(current.events) + 1, "info", "provider completed", {"terminal": True})],
                )
            )
            return super().mark_stale_nonterminal_attention(
                job_id,
                expected_status=expected_status,
                event=event,
            )

    jobs = CompletingJobs(tmp_path / "jobs.sqlite")
    jobs.save(_job("job-deploy", "linode_sketch_deploy", "running"))
    chains = ChainRepository(_chain(status="deploying", deploy_job_id="job-deploy"))

    recover_sketch_lifecycle(
        now=datetime(2026, 8, 4, 1, 0, tzinfo=timezone.utc),
        job_repository=jobs,
        sketch_repository=chains,
    )

    durable = jobs.get("job-deploy")
    assert durable.status == "succeeded"
    assert durable.input.get("lifecycleRecoveryAttention") is None
    assert durable.events[-1].message == "provider completed"


def test_startup_recovers_stale_outbound_parent_for_already_deployed_chain(tmp_path, monkeypatch):
    from app.services import sketch_chains

    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    parent = _job("job-outbound-auto-deploy-chain-1", "outbound_channel_auto_configuration", "running")
    jobs.save(
        replace(
            parent,
            input={
                "engagementId": "eng-1",
                "chainId": "chain-1",
                "deployJobId": "job-deploy",
                "channelIds": ["channel-1"],
                "claimOwner": "dead-runtime",
                "claimToken": "dead-token",
                "claimExpiresAt": "2026-08-04T00:05:00+00:00",
            },
        )
    )
    chains = ChainRepository(_chain(status="pending", deploy_job_id=""))
    scheduled = []
    sketch_chains._outbound_auto_configuration_active.clear()
    monkeypatch.setattr("app.services.sketch_chains.start_runtime_task", lambda task, **kwargs: scheduled.append(task))

    outcomes = recover_sketch_lifecycle(
        startup=True,
        now=datetime(2026, 8, 4, 1, 0, tzinfo=timezone.utc),
        job_repository=jobs,
        sketch_repository=chains,
    )
    repeated = recover_sketch_lifecycle(
        startup=True,
        now=datetime(2026, 8, 4, 1, 1, tzinfo=timezone.utc),
        job_repository=jobs,
        sketch_repository=chains,
    )

    assert any(outcome["state"] == "configuration_recovered" for outcome in outcomes)
    assert not any(outcome["state"] == "configuration_recovered" for outcome in repeated)
    assert len(scheduled) == 1
    durable = jobs.get(parent.id)
    assert durable.input["claimOwner"] == sketch_chains._outbound_auto_configuration_owner
    assert durable.input["claimToken"] != "dead-token"
    sketch_chains._outbound_auto_configuration_active.clear()


def test_startup_creates_continuation_with_edges_recorded_after_original_plan(tmp_path, monkeypatch):
    from app.services import sketch_chains

    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    deploy = _job("job-deploy", "mixed_provider_sketch_deploy", "succeeded", topology=True)
    jobs.save(
        replace(
            deploy,
            events=deploy.events
            + [
                JobEvent(
                        3,
                    "info",
                    "expanded edge channels recorded",
                    {
                        "outboundChannels": [
                            {"chainId": "chain-1", "channelId": "chain-1-edge-01"},
                            {"chainId": "chain-1", "channelId": "chain-1-edge-02"},
                        ]
                    },
                )
            ],
        )
    )
    chains = ChainRepository(_chain(status="deployed", deploy_job_id="job-deploy", nodes=[{"hostname": "edge-1"}]))
    scheduled = []
    sketch_chains._outbound_auto_configuration_active.clear()
    monkeypatch.setattr("app.services.sketch_chains.start_runtime_task", lambda task, **kwargs: scheduled.append(task))

    recover_sketch_lifecycle(startup=True, job_repository=jobs, sketch_repository=chains)

    parent = jobs.get("job-outbound-auto-deploy-chain-1")
    assert parent is not None
    assert parent.input["channelIds"] == ["chain-1-edge-01", "chain-1-edge-02"]
    assert len(scheduled) == 1
    sketch_chains._outbound_auto_configuration_active.clear()


def _chain(
    *,
    status: str,
    deploy_job_id: str,
    teardown_job_id: str = "",
    nodes=None,
) -> StoredSketchChain:
    return StoredSketchChain(
        chain_id="chain-1",
        engagement_id="eng-1",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="small",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="small",
        status=status,
        burned=False,
        burned_note="",
        deploy_job_id=deploy_job_id,
        teardown_job_id=teardown_job_id,
        terraform_working_directory="",
        nodes=list(nodes or []),
        created_at="2026-08-03T00:00:00+00:00",
        updated_at="2026-08-03T00:00:00+00:00",
    )


def _job(job_id: str, action: str, status: str, *, topology: bool = False) -> StoredJobRun:
    data = {
        "sketchInfrastructure": [
            {"hostname": "edge-1", "provider": "linode", "role": "edge", "status": "deployed"}
        ]
    } if topology else {}
    events = [JobEvent(1, "info", "provider state", data)]
    if topology and status == "succeeded":
        events.append(JobEvent(2, "info", "bootstrap", {"bootstrap": "succeeded"}))
    return StoredJobRun(
        id=job_id,
        action=action,
        status=status,
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={"engagementId": "eng-1", "terraformWorkingDirectory": "/tmp/sketch"},
        artifact_refs=[],
        created_at="2026-08-03T00:00:00+00:00",
        started_at="2026-08-03T00:00:00+00:00",
        finished_at="2026-08-03T00:01:00+00:00" if status != "running" else None,
        events=events,
    )
