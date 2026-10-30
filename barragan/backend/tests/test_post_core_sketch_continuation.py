# Copyright (c) 2026, Oracle and/or its affiliates.
from dataclasses import replace
from pathlib import Path
import threading

from app.services import post_core_sketch_continuation as continuation
from app.storage.job_repository import SqlAlchemyJobRepository, SqliteJobRepository, StoredJobRun
from app.storage.sketch_chain_repository import StoredSketchChain


class FakeSketchRepository:
    def __init__(self, chains: list[StoredSketchChain]):
        self.chains = {(chain.engagement_id, chain.chain_id): chain for chain in chains}

    def list_for_engagement(self, engagement_id: str) -> list[StoredSketchChain]:
        return [chain for (engagement, _), chain in self.chains.items() if engagement == engagement_id]

    def get(self, engagement_id: str, chain_id: str) -> StoredSketchChain | None:
        return self.chains.get((engagement_id, chain_id))

    def save(self, chain: StoredSketchChain) -> StoredSketchChain:
        self.chains[(chain.engagement_id, chain.chain_id)] = chain
        return chain


def test_snapshot_and_continuation_dispatch_only_the_core_owned_pending_ids(tmp_path: Path):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    sketches = FakeSketchRepository(
        [
            _chain("chain-a", "pending"),
            _chain("chain-b", "deployed", deploy_job_id="job-existing"),
        ]
    )
    snapshot = continuation.snapshot_pending_sketch_chain_ids("eng-1", repository=sketches)
    assert snapshot == ["chain-a"]
    core = jobs.save(_core_job(snapshot))

    # A chain created after core start is deliberately outside the snapshot.
    sketches.save(_chain("chain-later", "pending"))
    calls: list[str] = []

    def dispatch(_engagement_id, chain_id, _body):
        calls.append(chain_id)
        sketches.save(replace(sketches.get("eng-1", chain_id), status="deploying", deploy_job_id=f"job-{chain_id}"))
        return {"job": {"id": f"job-{chain_id}"}}

    parent = continuation.start_post_core_sketch_continuation(
        core.id,
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=dispatch,
        background_runner=lambda task: task(),
    )
    repeated = continuation.start_post_core_sketch_continuation(
        core.id,
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=dispatch,
        background_runner=lambda task: task(),
    )

    assert parent is not None and repeated is not None
    assert parent.id == repeated.id
    assert repeated.status == "succeeded"
    assert calls == ["chain-a"]
    assert repeated.input["outcomes"] == {"chain-a": {"state": "dispatched", "jobId": "job-chain-a"}}
    assert "chain-later" not in repeated.input["outcomes"]


def test_continuation_treats_already_deploying_chain_as_dispatch_evidence(tmp_path: Path):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    sketches = FakeSketchRepository([_chain("chain-a", "deploying", deploy_job_id="job-child")])
    core = jobs.save(_core_job(["chain-a"]))

    parent = continuation.start_post_core_sketch_continuation(
        core.id,
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=lambda *_args: (_ for _ in ()).throw(AssertionError("must not dispatch")),
        background_runner=lambda task: task(),
    )

    assert parent is not None and parent.status == "succeeded"
    assert parent.input["outcomes"]["chain-a"] == {
        "state": "already_started",
        "chainStatus": "deploying",
        "jobId": "job-child",
    }


def test_exact_plan_continuation_rejects_intent_changed_after_review():
    from app.asgi import create_app
    from app.core.config import TestConfig

    app = create_app(TestConfig)
    sketches = FakeSketchRepository([_chain("chain-a", "pending")])
    reviewed_fingerprint = continuation.sketch_chain_intent_fingerprint(sketches.get("eng-1", "chain-a"))
    scheduled = []
    calls: list[str] = []

    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        core = jobs.save(
            replace(
                _core_job(["chain-a"]),
                id="job-core-exact-race",
                input={
                    **_core_job(["chain-a"]).input,
                    "corePlanId": "dpl-exact-race",
                    "pendingSketchChainFingerprints": {"chain-a": reviewed_fingerprint},
                },
            )
        )
        queued = continuation.start_post_core_sketch_continuation(
            core.id,
            job_repository=jobs,
            sketch_repository=sketches,
            dispatcher=lambda _eng, chain, _body: calls.append(chain) or {"job": {"id": "job-child"}},
            background_runner=scheduled.append,
        )
        assert queued is not None and queued.status == "queued"

        current = sketches.get("eng-1", "chain-a")
        sketches.save(replace(current, edge_region="us-east", updated_at="2026-08-02T00:02:00+00:00"))
        scheduled[0]()

        completed = jobs.get(queued.id)
        assert completed is not None and completed.status == "failed"
        assert calls == []
        assert completed.input["outcomes"]["chain-a"] == {
            "state": "failed",
            "error": "snapshotted chain intent changed after core plan review",
        }


def test_failed_parent_is_not_automatically_retried_but_has_explicit_retry(tmp_path: Path):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    sketches = FakeSketchRepository([_chain("chain-a", "pending")])
    core = jobs.save(_core_job(["chain-a"]))

    failed = continuation.start_post_core_sketch_continuation(
        core.id,
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=lambda *_args: (_ for _ in ()).throw(RuntimeError("ambiguous provider failure")),
        background_runner=lambda task: task(),
    )
    assert failed is not None and failed.status == "failed"

    calls: list[str] = []
    recovered = continuation.recover_post_core_sketch_continuations(
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=lambda _eng, chain, _body: calls.append(chain) or {"job": {"id": "job-retry"}},
        background_runner=lambda task: task(),
    )
    assert recovered == [failed.id]
    assert calls == []
    assert jobs.get(failed.id).status == "failed"

    retried = continuation.start_post_core_sketch_continuation(
        core.id,
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=lambda _eng, chain, _body: calls.append(chain) or {"job": {"id": "job-retry"}},
        background_runner=lambda task: task(),
        retry_failed=True,
    )
    assert retried is not None and retried.status == "succeeded"
    assert calls == ["chain-a"]


def test_recovery_reclaims_queued_parent_but_ignores_destroy_after_validation_core(tmp_path: Path):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    sketches = FakeSketchRepository([_chain("chain-a", "pending")])
    retained = jobs.save(_core_job(["chain-a"]))
    destroyed = jobs.save(
        replace(
            _core_job(["chain-a"], job_id="job-core-destroyed"),
            input={
                **_core_job(["chain-a"]).input,
                "postCoreSketchContinuationEligible": False,
                "deploymentMode": "destroy_after_validation",
            },
        )
    )
    scheduled = []
    queued = continuation.start_post_core_sketch_continuation(
        retained.id,
        job_repository=jobs,
        sketch_repository=sketches,
        background_runner=scheduled.append,
    )
    assert queued is not None and queued.status == "queued"

    jobs.save(replace(queued, input={**queued.input, "claimExpiresAt": "2026-01-01T00:00:00+00:00"}))
    calls: list[str] = []
    recovered = continuation.recover_post_core_sketch_continuations(
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=lambda _eng, chain, _body: calls.append(chain) or {"job": {"id": "job-child"}},
        background_runner=lambda task: task(),
    )

    assert recovered == [queued.id]
    assert calls == ["chain-a"]
    assert jobs.get(queued.id).status == "succeeded"
    assert jobs.get(f"job-post-core-sketch-{destroyed.id.removeprefix('job-')}") is None


def test_recovery_monitor_reconsiders_live_startup_lease_after_expiry(tmp_path: Path):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    sketches = FakeSketchRepository([_chain("chain-a", "pending")])
    core = jobs.save(_core_job(["chain-a"]))
    stale_runtime_tasks = []
    parent = continuation.start_post_core_sketch_continuation(
        core.id,
        job_repository=jobs,
        sketch_repository=sketches,
        background_runner=stale_runtime_tasks.append,
    )
    assert parent is not None and parent.status == "queued"

    # Startup recovery sees a still-live foreign lease and safely leaves it.
    continuation.recover_post_core_sketch_continuations(
        job_repository=jobs,
        sketch_repository=sketches,
        background_runner=stale_runtime_tasks.append,
    )
    assert len(stale_runtime_tasks) == 1

    dispatch_calls: list[str] = []

    def expire_lease(_seconds: float) -> bool:
        live = jobs.get(parent.id)
        jobs.save(replace(live, input={**live.input, "claimExpiresAt": "2026-01-01T00:00:00+00:00"}))
        return False

    continuation.run_post_core_sketch_recovery_monitor(
        job_repository=jobs,
        sketch_repository=sketches,
        dispatcher=lambda _eng, chain, _body: dispatch_calls.append(chain) or {"job": {"id": "job-child"}},
        background_runner=lambda task: task(),
        wait=expire_lease,
        interval_seconds=0,
        max_cycles=1,
    )
    # Even if the old runtime wakes later, its persisted token is no longer valid.
    stale_runtime_tasks[0]()

    assert dispatch_calls == ["chain-a"]
    assert jobs.get(parent.id).status == "succeeded"


def test_recovery_monitor_continues_after_transient_cycle_failure(monkeypatch):
    cycles: list[str] = []

    def recover(**_kwargs):
        cycles.append("attempt")
        if len(cycles) == 1:
            raise RuntimeError("transient sqlite busy")
        cycles.append("succeeded")
        return []

    monkeypatch.setattr(continuation, "recover_post_core_sketch_continuations", recover)
    continuation.run_post_core_sketch_recovery_monitor(
        wait=lambda _seconds: False,
        interval_seconds=0,
        max_cycles=2,
    )

    assert cycles == ["attempt", "attempt", "succeeded"]


def test_atomic_lease_allows_only_one_dispatch_across_runtime_repositories(tmp_path: Path):
    database_path = tmp_path / "jobs.sqlite"
    seed_jobs = SqliteJobRepository(database_path)
    seed_jobs.save(_core_job(["chain-a"]))
    sketches = FakeSketchRepository([_chain("chain-a", "pending")])
    repositories = [SqliteJobRepository(database_path), SqliteJobRepository(database_path)]
    dispatcher_barrier = threading.Barrier(2)
    dispatch_calls: list[str] = []
    task_threads: list[threading.Thread] = []

    def dispatch(_engagement_id, chain_id, _body):
        dispatch_calls.append(chain_id)
        dispatcher_barrier.wait(timeout=2)
        sketches.save(replace(sketches.get("eng-1", chain_id), status="deploying", deploy_job_id="job-child"))
        return {"job": {"id": "job-child"}}

    def run_in_background(task):
        thread = threading.Thread(target=task)
        task_threads.append(thread)
        thread.start()

    starters = [
        threading.Thread(
            target=continuation.start_post_core_sketch_continuation,
            args=("job-core-1",),
            kwargs={
                "job_repository": repository,
                "sketch_repository": sketches,
                "dispatcher": dispatch,
                "background_runner": run_in_background,
            },
        )
        for repository in repositories
    ]
    for thread in starters:
        thread.start()
    for thread in starters:
        thread.join(timeout=2)

    dispatcher_barrier.wait(timeout=2)
    for thread in task_threads:
        thread.join(timeout=2)

    assert dispatch_calls == ["chain-a"]
    assert len(task_threads) == 1
    parent = seed_jobs.get("job-post-core-sketch-core-1")
    assert parent is not None and parent.status == "succeeded"


def test_sqlalchemy_repository_create_and_claim_are_single_winner():
    from app.asgi import create_app
    from app.core.config import TestConfig

    app = create_app(TestConfig)
    with app.storage_context():
        jobs = SqlAlchemyJobRepository()
        candidate = replace(
            _core_job([]),
            id="job-parent",
            action=continuation.POST_CORE_SKETCH_CONTINUATION_ACTION,
            status="queued",
        )
        first = jobs.save_if_absent(candidate)
        second = jobs.save_if_absent(replace(candidate, requested_by="other-runtime"))
        claim_one = jobs.claim_lease(
            first.id,
            owner="runtime-one",
            token="token-one",
            claimed_at="2026-08-02T00:00:00+00:00",
            expires_at="2099-08-02T00:00:00+00:00",
            eligible_statuses={"queued", "running"},
        )
        claim_two = jobs.claim_lease(
            first.id,
            owner="runtime-two",
            token="token-two",
            claimed_at="2026-08-02T00:00:00+00:00",
            expires_at="2099-08-02T00:00:00+00:00",
            eligible_statuses={"queued", "running"},
        )

    assert second.requested_by == candidate.requested_by
    assert claim_one is not None and claim_one.input["claimToken"] == "token-one"
    assert claim_two is None


def _core_job(chain_ids: list[str], *, job_id: str = "job-core-1") -> StoredJobRun:
    return StoredJobRun(
        id=job_id,
        action=continuation.PILOT_CORE_ACTION,
        status="succeeded",
        target="engagement:eng-1",
        target_type="engagement",
        target_id="eng-1",
        requested_by="operator",
        input={
            "engagementId": "eng-1",
            "deploymentMode": "hold_for_review",
            "pendingSketchChainIds": chain_ids,
            "postCoreSketchContinuationEligible": True,
        },
        artifact_refs=[],
        created_at="2026-08-02T00:00:00+00:00",
        started_at="2026-08-02T00:00:01+00:00",
        finished_at="2026-08-02T00:01:00+00:00",
        events=[],
    )


def _chain(chain_id: str, status: str, *, deploy_job_id: str = "") -> StoredSketchChain:
    return StoredSketchChain(
        chain_id=chain_id,
        engagement_id="eng-1",
        assigned_proxy="proxy01",
        middle_provider="linode",
        middle_region="us-sea",
        middle_size="g6-nanode-1",
        edge_provider="linode",
        edge_region="us-sea",
        edge_size="g6-nanode-1",
        edge_count=1,
        edge_intents=[],
        status=status,
        burned=False,
        burned_note="",
        deploy_job_id=deploy_job_id,
        teardown_job_id="",
        terraform_working_directory="",
        nodes=[],
        created_at="2026-08-02T00:00:00+00:00",
        updated_at="2026-08-02T00:00:00+00:00",
    )
