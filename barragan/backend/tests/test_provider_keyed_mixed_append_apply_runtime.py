# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dispatch boundaries for the one-click paired append continuation.

These tests exercise sequencing and restart decisions. The child, provider,
host, and publication modules retain their own persisted proof tests.
"""

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_mixed_append_apply_runtime as runtime
from app.storage.job_repository import StoredJobRun


PARENT_ID = "job-provider-keyed-mixed-append-core"


def _job(job_id, action, status="running", *, inputs=None, events=None):
    return StoredJobRun(
        job_id, action, status, "engagement:eng-test", "engagement",
        "eng-test", "operator", inputs or {}, [], "2026-10-19T00:00:00+00:00",
        "2026-10-19T00:00:01+00:00", None, events or [],
    )


class _Jobs:
    def __init__(self, parent, first=None, second=None, host=None):
        self.rows = {row.id: row for row in (parent, first, second, host) if row is not None}
        self.claims = []

    def get(self, job_id):
        return self.rows.get(job_id)

    def claim_lease(self, job_id, **kwargs):
        self.claims.append((job_id, kwargs))
        saved = self.rows[job_id]
        updated = replace(saved, input={**saved.input,
            "claimOwner": kwargs["owner"], "claimToken": kwargs["token"],
            "claimClaimedAt": kwargs["claimed_at"],
            "claimHeartbeatAt": kwargs["claimed_at"],
            "claimExpiresAt": kwargs["expires_at"]})
        self.rows[job_id] = updated
        return updated


def _case(order):
    parent = _job(PARENT_ID, "provider_keyed_mixed_append", inputs={
        "phase": "apply_sealed", "corePlanId": "plan-core",
        "coreJobId": "job-core", "reviewSha256": "a" * 64,
        "providerOrder": list(order),
    })
    first_id = runtime.first_child_id(PARENT_ID)
    second_id = runtime.second_child_id(PARENT_ID)
    host_id = runtime.host_child_id(PARENT_ID)
    jobs = _Jobs(parent)
    trace = []
    source = SimpleNamespace(before_chains=("old-a", "old-b"),
                             chains=("new-a", "new-b"))
    receipt = SimpleNamespace(claim_owner="host-owner", claim_token="host-token")

    def binding(which):
        def build(*args, **kwargs):
            trace.append(f"{which}-binding")
            return {"binding": which}
        return build

    def apply(which, child_id):
        def run(*args, **kwargs):
            trace.append(f"{which}-apply")
            assert kwargs["binding"] == which
            child = _job(child_id, f"{which}-apply-child", inputs={
                "claimOwner": f"{which}-apply-owner", "claimToken": f"{which}-apply-token"}, events=[
                JobEvent(1, "info", "exact result", {})])
            jobs.rows[child_id] = child
            return child
        return run

    def proof(which, child_id):
        def finish(*args, **kwargs):
            trace.append(f"{which}-proof")
            assert kwargs["claim_owner"] == f"{which}-apply-owner"
            assert kwargs["claim_token"] == f"{which}-apply-token"
            child = replace(jobs.rows[child_id], status="succeeded")
            jobs.rows[child_id] = child
            return child
        return finish

    def collect(*args, **kwargs):
        trace.append("fresh-source")
        return source

    def host_proof(*args, **kwargs):
        trace.append("host-proof")
        assert kwargs["fresh_source"]() is source
        jobs.rows[host_id] = _job(host_id, "host-proof", "succeeded",
                                  inputs={"claimOwner": "host-owner",
                                          "claimToken": "host-token"})
        return receipt

    def validate(parent, child, saved_receipt, *, source):
        trace.append("host-receipt")
        assert saved_receipt is receipt
        return saved_receipt

    class Publisher:
        def publish_provider_keyed_mixed_append_pair(self, **kwargs):
            trace.append("publication")
            assert kwargs["provider_proof_children"] == {
                order[0]: jobs.rows[first_id], order[1]: jobs.rows[second_id]}
            assert kwargs["claim_owner"] == "host-owner"
            assert kwargs["claim_token"] == "host-token"
            assert kwargs["fresh_source"]() is source
            return ("published-a", "published-b")

    options = dict(
        environment="devtest", bootstrap_env={"BARRAGAN_TEMPLATE_ROOT": "/tmp/source"},
        job_repository=jobs, sketch_repository=object(),
        lease_lookup=lambda engagement: ("plan-core", "provider_keyed_mixed_append"),
        first_bindings_builder=binding("first"),
        first_apply_runner=apply("first", first_id),
        first_proof_finisher=proof("first", first_id),
        second_bindings_builder=binding("second"),
        second_apply_runner=apply("second", second_id),
        second_proof_finisher=proof("second", second_id),
        source_collector=collect, host_prover=host_proof,
        publisher=Publisher(),
    )
    return jobs, trace, options, validate


@pytest.mark.parametrize("order", [
    ("linode", "digitalocean"), ("digitalocean", "linode"),
])
def test_one_action_sequences_both_proofs_before_host_and_publication(monkeypatch, order):
    jobs, trace, options, validate = _case(order)
    monkeypatch.setattr(runtime, "validate_six_host_receipt_child", validate)
    assert runtime.advance_mixed_append_apply(PARENT_ID, **options) == (
        "published-a", "published-b")
    assert trace == [
        "first-binding", "first-apply", "first-proof",
        "second-binding", "second-apply", "second-proof",
        "fresh-source", "host-proof", "fresh-source", "host-receipt",
        "publication", "fresh-source",
    ]
    assert len(jobs.claims) == 1
    _, claim = jobs.claims[0]
    assert (datetime.fromisoformat(claim["expires_at"])
            - datetime.fromisoformat(claim["claimed_at"])) == timedelta(minutes=15)


@pytest.mark.parametrize("stopped", ["first", "second"])
def test_existing_command_intent_never_dispatches_apply(monkeypatch, stopped):
    jobs, trace, options, validate = _case(("linode", "digitalocean"))
    monkeypatch.setattr(runtime, "validate_six_host_receipt_child", validate)
    first = runtime.first_child_id(PARENT_ID)
    second = runtime.second_child_id(PARENT_ID)
    if stopped == "first":
        jobs.rows[first] = _job(first, "provider_keyed_mixed_append_apply_child",
                                events=[JobEvent(1, "info", "command intended", {})])
    else:
        jobs.rows[first] = replace(_job(first, "provider_keyed_mixed_append_apply_child"),
                                   status="succeeded")
        jobs.rows[second] = _job(second, "provider_keyed_mixed_append_second_apply_child",
                                 events=[JobEvent(1, "info", "command intended", {})])
    with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
        runtime.advance_mixed_append_apply(PARENT_ID, **{
            **options,
            "first_proof_finisher": lambda *args, **kwargs: (
                jobs.rows[first] if stopped == "second" else (_ for _ in ()).throw(
                    ValueError("uncertain first result"))),
            "second_proof_finisher": lambda *args, **kwargs: (_ for _ in ()).throw(
                ValueError("uncertain second result")),
        })
    assert "first-apply" not in trace
    assert "second-apply" not in trace
    assert "host-proof" not in trace


def test_nonterminal_host_child_blocks_recontact(monkeypatch):
    jobs, trace, options, validate = _case(("digitalocean", "linode"))
    monkeypatch.setattr(runtime, "validate_six_host_receipt_child", validate)
    for child_id in (runtime.first_child_id(PARENT_ID),
                     runtime.second_child_id(PARENT_ID)):
        jobs.rows[child_id] = replace(_job(child_id, "apply"), status="succeeded")
    host_id = runtime.host_child_id(PARENT_ID)
    jobs.rows[host_id] = _job(host_id, "host", status="running")
    options["first_proof_finisher"] = lambda *args, **kwargs: jobs.rows[
        runtime.first_child_id(PARENT_ID)]
    options["second_proof_finisher"] = lambda *args, **kwargs: jobs.rows[
        runtime.second_child_id(PARENT_ID)]
    with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
        runtime.advance_mixed_append_apply(PARENT_ID, **options)
    assert "host-proof" not in trace
    assert "publication" not in trace


def test_queued_host_child_is_sent_to_strict_never_started_worker(monkeypatch):
    jobs, trace, options, validate = _case(("digitalocean", "linode"))
    monkeypatch.setattr(runtime, "validate_six_host_receipt_child", validate)
    for child_id in (runtime.first_child_id(PARENT_ID), runtime.second_child_id(PARENT_ID)):
        jobs.rows[child_id] = replace(_job(child_id, "apply"), status="succeeded")
    jobs.rows[runtime.host_child_id(PARENT_ID)] = replace(
        _job(runtime.host_child_id(PARENT_ID), "host", status="queued"), started_at=None)
    options['first_proof_finisher'] = lambda *a, **kw: jobs.get(runtime.first_child_id(PARENT_ID))
    options['second_proof_finisher'] = lambda *a, **kw: jobs.get(runtime.second_child_id(PARENT_ID))
    assert runtime.advance_mixed_append_apply(PARENT_ID, **options) == ('published-a', 'published-b')
    assert trace.count('host-proof') == trace.count('publication') == 1
    assert 'first-apply' not in trace and 'second-apply' not in trace


def test_terminal_host_receipt_resumes_publication_without_recontact(monkeypatch):
    jobs, trace, options, _ = _case(("linode", "digitalocean"))
    for child_id in (runtime.first_child_id(PARENT_ID),
                     runtime.second_child_id(PARENT_ID)):
        jobs.rows[child_id] = replace(_job(child_id, "apply"), status="succeeded")
    host_id = runtime.host_child_id(PARENT_ID)
    jobs.rows[host_id] = replace(_job(
        host_id, "host", status="succeeded",
        inputs={"claimOwner": "host-owner", "claimToken": "host-token"},
        events=[JobEvent(1, "info", "mixed append six-host proof completed", {
            "sourceSha256": "a" * 64,
            "providerOrder": ["linode", "digitalocean"],
            "chainIds": ["chain-a", "chain-b"],
            "newEdgeAddresses": ["edge-a", "edge-b"],
            "newEdgeIds": ["node-a", "node-b"],
            "providerProofDigests": ["b" * 64, "c" * 64],
            "bootstrapEventDigests": ["d" * 64, "e" * 64],
            "sketchKnownHostsDigests": ["f" * 64, "0" * 64],
            "rawProbeDigests": ["1" * 64, "2" * 64],
        })]), finished_at="2026-10-19T00:01:00+00:00")
    options["first_proof_finisher"] = lambda *args, **kwargs: jobs.rows[
        runtime.first_child_id(PARENT_ID)]
    options["second_proof_finisher"] = lambda *args, **kwargs: jobs.rows[
        runtime.second_child_id(PARENT_ID)]

    def validate(parent, child, receipt, *, source):
        assert type(receipt) is runtime.SixHostProofReceipt
        assert receipt.claim_owner == "host-owner"
        assert receipt.claim_token == "host-token"
        return receipt

    monkeypatch.setattr(runtime, "validate_six_host_receipt_child", validate)
    # The original fake publisher expects only the returned claim identity.
    assert runtime.advance_mixed_append_apply(PARENT_ID, **options) == (
        "published-a", "published-b")
    assert "host-proof" not in trace
    assert trace.count("publication") == 1


def test_startup_recovers_only_approved_running_owned_parent(monkeypatch):
    jobs, _, _, _ = _case(("digitalocean", "linode"))
    parent = jobs.rows[PARENT_ID]
    approved = replace(parent, input={**parent.input, "engagementId": parent.target_id},
        events=[JobEvent(1, "info", "mixed append pair approved", {
            "reviewSha256": parent.input["reviewSha256"],
            "planChildId": runtime._plan_child_id(parent.id),
        })])
    rows = [
        approved,
        replace(approved, id="job-completed", status="succeeded"),
        replace(approved, id="job-failed", status="failed"),
        replace(approved, id="job-planning", input={**approved.input, "phase": "planning"}),
    ]
    observed_query = []
    def listed(**kwargs):
        observed_query.append(kwargs)
        return rows
    jobs.list_by_actions_and_statuses = listed
    called = []
    monkeypatch.setattr(runtime, "run_mixed_append_apply", called.append)
    callbacks = []
    ids = runtime.recover_approved_mixed_append_applies(
        environment="devtest", schedule=callbacks.append, job_repository=jobs,
        lease_lookup=lambda engagement: ("plan-core", "provider_keyed_mixed_append"))
    assert ids == [PARENT_ID]
    assert observed_query == [{"actions": {"provider_keyed_mixed_append"},
                               "statuses": {"running"}, "limit": 500}]
    assert len(callbacks) == 1
    callbacks[0]()
    assert called == [PARENT_ID]
    assert runtime.recover_approved_mixed_append_applies(
        environment="production", schedule=callbacks.append,
        job_repository=jobs) == []
    assert len(callbacks) == 1


def test_publication_claim_conflict_stops_after_terminal_host_proof(monkeypatch):
    jobs, trace, options, validate = _case(("linode", "digitalocean"))
    monkeypatch.setattr(runtime, "validate_six_host_receipt_child", validate)
    jobs.claim_lease = lambda *args, **kwargs: None
    with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
        runtime.advance_mixed_append_apply(PARENT_ID, **options)
    assert "host-proof" in trace
    assert "publication" not in trace
    assert jobs.get(runtime.host_child_id(PARENT_ID)).status == "succeeded"


@pytest.mark.parametrize("stage", ["first", "second"])
@pytest.mark.parametrize("mode", ["fresh", "active-restart", "expired-restart"])
def test_real_sql_proof_claim_handoff_never_borrows_a_restart_claim(monkeypatch, stage, mode):
    from app.storage.database import db
    from app.storage.job_repository import SqlAlchemyJobRepository
    from app.services import provider_keyed_mixed_append_first_proof_job as first_proof
    from app.services import provider_keyed_mixed_append_second_proof_job as second_proof

    fake_jobs, _trace, options, _validate = _case(("linode", "digitalocean"))
    parent = fake_jobs.get(PARENT_ID)
    child_id = (runtime.first_child_id if stage == "first" else runtime.second_child_id)(PARENT_ID)
    module = first_proof if stage == "first" else second_proof
    finisher = (first_proof.prove_and_finish_first_mixed_append_apply if stage == "first"
                else second_proof.prove_and_finish_second_mixed_append_apply)
    observed, dispatched, passed_claims = [], [], []
    state = db.configure("sqlite:///:memory:")
    jobs = SqlAlchemyJobRepository()

    def save_apply_claim():
        child = jobs.save(_job(child_id, f"{stage}-apply-child",
            events=[JobEvent(1, "info", "exact result awaiting proof", {})]))
        at = runtime._now()
        expired = mode == "expired-restart"
        claimed = jobs.claim_lease(child.id, owner=f"{stage}-apply-owner", token="apply-token",
            claimed_at=(at - timedelta(minutes=3) if expired else at).isoformat(),
            expires_at=(at - timedelta(minutes=1) if expired else at + timedelta(minutes=2)).isoformat(),
            eligible_statuses={"running"})
        assert claimed is not None
        return claimed

    def apply(*args, **kwargs):
        dispatched.append(stage)
        return save_apply_claim()

    def observer(**kwargs):
        # Reaching this callback proves the production proof finisher acquired
        # the SQL claim and passed its preceding source/journal/quiescence gates.
        observed.append(jobs.get(child_id).input["claimOwner"])
        raise ValueError("bounded test stops before any provider observation")

    journal = SimpleNamespace(started_identity={}, result_sha256="b" * 64)
    monkeypatch.setattr(module, "_journal", lambda *args: (journal, "awaiting"))
    source = SimpleNamespace(receipt_sha256="c" * 64, intent=object(),
        predecessor_state={}, reviewed_show_json={})

    def prove(*args, **kwargs):
        passed_claims.append({key: kwargs[key] for key in ("claim_owner", "claim_token") if key in kwargs})
        extra = {"first_terminal_proof": lambda *_: "a" * 64} if stage == "second" else {}
        return finisher(*args, **kwargs, source_loader=lambda *_: source,
            process_quiescent=lambda *_: True, poststate_observer=observer, **extra)

    with db.bind(state):
        db.create_all()
        jobs.save(parent)
        if stage == "second":
            first_id = runtime.first_child_id(PARENT_ID)
            jobs.save(_job(first_id, "first-apply-child", status="succeeded"))
            def terminal_first(*args, **kwargs):
                assert "claim_owner" not in kwargs and "claim_token" not in kwargs
                return jobs.get(first_id)
            options["first_proof_finisher"] = terminal_first
        if mode != "fresh":
            save_apply_claim()
        options.update(job_repository=jobs,
            **{f"{stage}_apply_runner": apply, f"{stage}_proof_finisher": prove})
        with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
            runtime.advance_mixed_append_apply(PARENT_ID, **options)
        owner = jobs.get(child_id).input["claimOwner"]
        assert dispatched == ([stage] if mode == "fresh" else [])
        if mode == "fresh":
            assert passed_claims == [{"claim_owner": f"{stage}-apply-owner", "claim_token": "apply-token"}]
            assert observed == [f"{stage}-apply-owner"]
            assert owner == f"{stage}-apply-owner"
        else:
            assert passed_claims == [{}]
            if mode == "active-restart":
                assert observed == [] and owner == f"{stage}-apply-owner"
            else:
                assert len(observed) == 1 and owner.startswith(f"mixed-append-{stage}-proof-")
                assert owner != f"{stage}-apply-owner"


def test_public_runtime_logs_suppressed_locations_without_exception_data(monkeypatch, caplog):
    class SecretError(ValueError):
        def __str__(self):
            pytest.fail("exception must never be formatted")

        def __repr__(self):
            pytest.fail("exception must never be represented")

    # Give the inner predicate an application filename, without reading or
    # logging source text; external test frames must not appear in the record.
    namespace = {"SecretError": SecretError}
    filename = str(runtime._APP_ROOT / "services" / "predicate.py")
    exec(compile("def fail():\n    raise SecretError('provider-token-secret')\n", filename, "exec"), namespace)

    def environment(_key):
        try:
            namespace["fail"]()
        except SecretError:
            raise RuntimeError("payload-secret") from None

    monkeypatch.setattr(runtime, "SqlAlchemyJobRepository", lambda: object())
    monkeypatch.setattr(runtime, "runtime_value", environment)
    with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
        runtime.run_mixed_append_apply(PARENT_ID)
    record = caplog.records[-1]
    assert record.exc_info is None and record.stack_info is None
    assert record.args[0] == [
        ("RuntimeError", [("provider_keyed_mixed_append_apply_runtime.py",
                           runtime.run_mixed_append_apply.__code__.co_firstlineno + 6)]),
        ("SecretError", [("predicate.py", 2)]),
    ]
    assert "provider-token-secret" not in caplog.text
    assert "payload-secret" not in caplog.text
    assert str(runtime._APP_ROOT) not in caplog.text
    assert Path(__file__).name not in caplog.text


def test_failure_locations_follow_both_links_and_bound_cycles(caplog):
    outer, cause, context = RuntimeError("secret-a"), ValueError("secret-b"), TypeError("secret-c")
    outer.__cause__, outer.__context__ = cause, context
    cause.__context__ = outer
    runtime._log_runtime_failure(outer)
    assert caplog.records[-1].args[0] == [
        ("RuntimeError", []), ("ValueError", []), ("TypeError", [])]
    cursor = outer
    for _ in range(30):
        cursor.__cause__ = RuntimeError("secret-deep")
        cursor = cursor.__cause__
    runtime._log_runtime_failure(outer)
    assert len(caplog.records[-1].args[0]) == 16
    assert "secret-" not in caplog.text


@pytest.fixture(autouse=True)
def isolate_purchase_catalog(monkeypatch):
    monkeypatch.setattr(runtime, "require_reviewed_mixed_append_availability", lambda *args, **kwargs: None)


def test_pristine_dispatch_checks_catalog_before_any_child_or_binding(monkeypatch):
    from app.services.provider_keyed_mixed_append_availability import MixedAppendAvailabilityAttention
    jobs, trace, options, validate = _case(("linode", "digitalocean"))
    def unavailable(*args, **kwargs):
        trace.append("catalog-blocked")
        raise MixedAppendAvailabilityAttention("DigitalOcean availability unavailable; no append started")
    monkeypatch.setattr(runtime, "require_reviewed_mixed_append_availability", unavailable)
    with pytest.raises(runtime.MixedAppendApplyRuntimeAttention):
        runtime.advance_mixed_append_apply(PARENT_ID, **options)
    assert trace == ["catalog-blocked"]
    assert jobs.get(runtime.first_child_id(PARENT_ID)) is None
    assert jobs.get(runtime.second_child_id(PARENT_ID)) is None
    assert jobs.claims == []
