# Copyright (c) 2026, Oracle and/or its affiliates.
"""GET-only attachment recheck never recreates provider work or replays apply."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import provider_keyed_initial_attachment_recheck as service
from app.services import provider_keyed_initial_continuation as continuation
from app.services.provider_keyed_digitalocean_attachment import DigitalOceanAttachmentStillSettling
from app.storage.job_repository import SqliteJobRepository
from test_provider_keyed_initial_continuation import _core


def _iso(seconds=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _fixture(tmp_path):
    jobs = SqliteJobRepository(tmp_path / "attachment.sqlite")
    core = jobs.save(_core())
    parent_id, plan_job_id, apply_job_id = continuation._job_ids(core.id)
    parent = continuation._new_job(
        parent_id, continuation.ACTION, core, "eng-opaque",
        {"engagementId": "eng-opaque", "coreJobId": core.id, "corePlanId": "plan-opaque",
         "planJobId": plan_job_id, "applyJobId": apply_job_id,
         "phase": "attachment_pending", "mutation": True,
         "nextAttachmentCheckAt": _iso(-120), "attachmentRecheckCount": 0,
         "claimOwner": "previous-worker", "claimToken": "previous-token", "claimExpiresAt": _iso(-60)},
    )
    jobs.save(replace(parent, status="running", started_at=_iso(-240)))
    plan = SimpleNamespace(id="plan-opaque", engagement_id="eng-opaque", status="applied",
                           apply_job_id=core.id, evidence={"sketchStateSchema": "provider-keyed-v2"})
    plans = SimpleNamespace(get=lambda identifier: plan if identifier == plan.id else None)
    intent = SimpleNamespace(state_sha256="a" * 64, firewall_id="opaque-firewall",
                             nodes=(SimpleNamespace(droplet_id="101"),))
    proof = SimpleNamespace(state_sha256=intent.state_sha256, firewall_id=intent.firewall_id,
                            verified_droplet_ids=("101",), provider_membership_verified=True,
                            host_policy_verified=False, attempts=2)
    calls = []
    def preflight(*_args, **_kwargs):
        calls.append("preflight")
        return (object(), object(), {}, object())
    def adapter(*_args):
        calls.append("adapter")
        return intent
    def reconciler(*_args, **_kwargs):
        calls.append("get")
        return proof
    options = dict(
        environment="devtest", state_root=Path("/tmp/unused-state"), job_repository=jobs,
        plan_repository=plans, credential_repository=object(),
        lease_lookup=lambda _id: ("plan-opaque", "provider_keyed_initial"),
        postapply_preflight=preflight, attachment_intent_builder=adapter,
        attachment_reconciler=reconciler, clock=_iso,
    )
    return jobs, parent_id, options, calls, intent, proof


def test_late_settlement_records_proof_once_without_apply_replay(tmp_path):
    jobs, parent_id, options, calls, intent, proof = _fixture(tmp_path)
    result = service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert result.status == "running" and result.input["phase"] == "awaiting_host_proof"
    assert datetime.fromisoformat(result.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
    assert "nextAttachmentCheckAt" not in result.input
    assert "attachmentRecheckCount" not in result.input
    assert result.events[-1].data == {
        "stateSha256": intent.state_sha256, "firewallId": intent.firewall_id,
        "verifiedDropletIds": ["101"], "attempts": 2,
        "providerMembershipVerified": True, "hostProofPending": True,
    }
    assert calls == ["preflight", "adapter", "get"]
    successor = jobs.claim_lease(
        parent_id, owner="host-binder", token="host-token", claimed_at=_iso(),
        expires_at=_iso(3600), eligible_statuses={"running"},
        eligible_phases={"awaiting_host_proof"},
    )
    assert successor is not None and successor.input["claimToken"] == "host-token"
    assert jobs.save_if_leased(result, owner=service._CLAIM_OWNER,
                               token=result.input["claimToken"]) is None
    with pytest.raises(service.ProviderKeyedInitialAttachmentRecheckError):
        service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert calls == ["preflight", "adapter", "get"]
    assert all(job.action != "provider_keyed_initial_apply" for job in jobs.list())


def test_still_settling_persists_bounded_backoff_and_rechecks_when_due(tmp_path):
    jobs, parent_id, options, calls, _intent, proof = _fixture(tmp_path)
    outcomes = [DigitalOceanAttachmentStillSettling("secret provider detail"), proof]
    def reconciler(*_args, **_kwargs):
        calls.append("get")
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    options["attachment_reconciler"] = reconciler
    pending = service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert pending.status == "running" and pending.input["phase"] == "attachment_pending"
    assert pending.input["attachmentRecheckCount"] == 1
    assert pending.input["claimExpiresAt"] == pending.input["nextAttachmentCheckAt"]
    assert 0 < (datetime.fromisoformat(pending.input["nextAttachmentCheckAt"])
                - datetime.now(timezone.utc)).total_seconds() <= 60
    assert "secret provider detail" not in str(pending.events)
    with pytest.raises(service.ProviderKeyedInitialAttachmentRecheckError, match="not due"):
        service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert len(outcomes) == 1
    due = datetime.fromisoformat(pending.input["nextAttachmentCheckAt"]) + timedelta(seconds=1)
    options["clock"] = lambda: due.isoformat()
    complete = service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert complete.input["phase"] == "awaiting_host_proof"
    assert datetime.fromisoformat(complete.input["claimExpiresAt"]) <= datetime.now(timezone.utc)
    assert "nextAttachmentCheckAt" not in complete.input
    assert "attachmentRecheckCount" not in complete.input
    assert calls == ["preflight", "adapter", "get"] * 2


@pytest.mark.parametrize("failure", ["proof", "preflight", "lease"])
def test_hard_mismatch_or_evidence_drift_records_redacted_attention(tmp_path, failure):
    jobs, parent_id, options, calls, _intent, proof = _fixture(tmp_path)
    if failure == "proof":
        options["attachment_reconciler"] = lambda *_a, **_kw: replace(proof, firewall_id="wrong") if hasattr(proof, "__dataclass_fields__") else SimpleNamespace(**{**vars(proof), "firewall_id": "wrong"})
    elif failure == "preflight":
        options["postapply_preflight"] = lambda *_a, **_kw: (_ for _ in ()).throw(ValueError("secret state drift"))
    else:
        count = iter([("plan-opaque", "provider_keyed_initial"),
                      ("plan-opaque", "provider_keyed_initial"), ("other", "provider_keyed_initial")])
        options["lease_lookup"] = lambda _id: next(count)
    result = service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert "secret state drift" not in str(result.events)
    with pytest.raises(service.ProviderKeyedInitialAttachmentRecheckError):
        service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert all(job.action != "provider_keyed_initial_apply" for job in jobs.list())


def test_stale_worker_cannot_overwrite_new_phase_after_claim_theft(tmp_path):
    jobs, parent_id, options, calls, _intent, _proof = _fixture(tmp_path)
    second = SqliteJobRepository(jobs.database_path)
    def raced_preflight(*_args, **_kwargs):
        stolen = second.claim_lease(
            parent_id, owner="new-worker", token="new-token", claimed_at=_iso(4000),
            expires_at=_iso(4100), eligible_statuses={"running"},
            eligible_phases={"reconciling_attachment"},
        )
        assert stolen is not None
        second.save_if_leased(
            replace(stolen, input={**stolen.input, "phase": "awaiting_host_proof"}),
            owner="new-worker", token="new-token",
        )
        return (object(), object(), {}, object())
    options["postapply_preflight"] = raced_preflight
    with pytest.raises(service.ProviderKeyedInitialAttachmentRecheckError, match="reconciliation required"):
        service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert jobs.get(parent_id).input["phase"] == "awaiting_host_proof"
    assert jobs.get(parent_id).input["claimToken"] == "new-token"
    assert calls == ["adapter", "get"]


def test_core_lease_drift_while_still_settling_records_attention(tmp_path):
    jobs, parent_id, options, _calls, _intent, _proof = _fixture(tmp_path)
    observations = iter([("plan-opaque", "provider_keyed_initial"),
                         ("plan-opaque", "provider_keyed_initial"),
                         ("other-plan", "provider_keyed_initial")])
    options["lease_lookup"] = lambda _id: next(observations)
    options["attachment_reconciler"] = lambda *_a, **_kw: (_ for _ in ()).throw(
        DigitalOceanAttachmentStillSettling("secret transport detail"))
    result = service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert result.status == "failed" and result.input["phase"] == "attention"
    assert "secret transport detail" not in str(result.events)
    assert all(job.action != "provider_keyed_initial_apply" for job in jobs.list())


def test_moved_future_check_after_claim_releases_claim_at_new_due_time(tmp_path):
    jobs, parent_id, options, calls, _intent, _proof = _fixture(tmp_path)
    original_claim = jobs.claim_lease
    moved_check = _iso(120)

    def racing_claim(*args, **kwargs):
        current = jobs.get(parent_id)
        jobs.save(replace(current, input={**current.input, "nextAttachmentCheckAt": moved_check}))
        return original_claim(*args, **kwargs)

    jobs.claim_lease = racing_claim
    with pytest.raises(service.ProviderKeyedInitialAttachmentRecheckError, match="not due"):
        service.recheck_digitalocean_initial_attachment(parent_id, **options)
    deferred = jobs.get(parent_id)
    assert deferred.status == "running" and deferred.input["phase"] == "attachment_pending"
    assert deferred.input["claimExpiresAt"] == moved_check
    assert deferred.events[-1].message == "provider attachment recheck deferred to current schedule"
    assert calls == []

    jobs.claim_lease = original_claim
    options["clock"] = lambda: (datetime.fromisoformat(moved_check) + timedelta(seconds=1)).isoformat()
    result = service.recheck_digitalocean_initial_attachment(parent_id, **options)
    assert result.input["phase"] == "awaiting_host_proof"
    assert calls == ["preflight", "adapter", "get"]
