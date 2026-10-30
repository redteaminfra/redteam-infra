# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted dormant mixed-plan parent and real reviewed-order ordinal ledger."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_initial_plan_parent as parent_service
import app.services.provider_keyed_mixed_linode_intent as linode_compiler
import app.services.provider_keyed_mixed_linode_saved_plan as linode_saved
import app.services.provider_keyed_mixed_digitalocean_saved_plan as do_saved
from app.services.provider_keyed_mixed_digitalocean_intent import compile_mixed_digitalocean_initial_intent
from app.services.provider_keyed_sketch import prepare_provider_keyed_workspace, reserve_provider_topology, read_provider_topology
from app.services.sketch_ssh_keys import SketchSshKeyMaterial, SketchSshKeyMetadata, _fingerprint
from app.storage.job_repository import SqliteJobRepository, job_event_digest
from app.domain import JobEvent
from test_provider_keyed_mixed_digitalocean_intent import _mixed_records, PUBLIC_KEY
from test_provider_keyed_sketch import _source


@pytest.fixture(params=[True, False], ids=["linode-first", "digitalocean-first"])
def case(tmp_path, monkeypatch, request):
    records = _mixed_records(linode_first=request.param, same_region=True)
    material = SketchSshKeyMaterial(
        SketchSshKeyMetadata("eng-opaque", "private", "public", _fingerprint(PUBLIC_KEY),
                             [], "now", "now"), "private-key", PUBLIC_KEY)
    for module in (linode_compiler, linode_saved, do_saved):
        monkeypatch.setattr(module, "retrieve_sketch_ssh_key", lambda *a: material)
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    jobs.save(records["core_job"])
    source, revision = _source(tmp_path)
    state_root = tmp_path / "state"
    calls = []
    failures = {"provider": None}
    receipts = {}
    lease = {"value": ("plan-1", "provider_keyed_initial")}

    def fake_runner(provider):
        def run(**kwargs):
            assert kwargs["environment"] == "devtest"
            assert kwargs["lease_owner"] == "plan-1"
            if provider == "linode":
                intent = linode_compiler.compile_mixed_linode_initial_intent(
                    **{**records, "job_repository": jobs})
            else:
                intent = compile_mixed_digitalocean_initial_intent(
                    **{**records, "job_repository": jobs})
            calls.append(provider)
            if failures["provider"] == provider:
                failures["provider"] = None
                raise RuntimeError("injected interrupted provider plan")
            workspace = prepare_provider_keyed_workspace(
                "eng-opaque", provider, intent.provider_connection_id,
                template_root=source, source_revision=revision, root=state_root,
                environment="devtest", deployment_target="barragan-testing")
            if provider in receipts:
                assert read_provider_topology(workspace) == intent.topology
                return receipts[provider]
            topology = reserve_provider_topology(
                workspace, intent.topology["middles"], intent.topology["edge_groups"])
            assert topology == intent.topology
            fixed = lambda value: hashlib.sha256(f"{provider}:{value}".encode()).hexdigest()
            receipts[provider] = {
                "schema": f"mixed-{provider}-saved-plan-v1", "engagementId": "eng-opaque",
                "coreJobId": "job-core", "corePlanId": "plan-1", "revisionId": "rev-1",
                "reviewFingerprint": intent.review_fingerprint,
                "connectionId": intent.provider_connection_id,
                "credentialSecretSha256": intent.credential_secret_sha256,
                "credentialUpdatedAt": intent.credential_updated_at,
                "stateAbsent": True, "planSha256": fixed("plan"),
                "journalSha256": fixed("journal"), "sourceSha256": fixed("source"),
                "lockfileSha256": fixed("lock"), "topologySha256": fixed("topology"),
                "inputSha256": fixed("input"), "showJsonSha256": fixed("show"),
            }
            return receipts[provider]
        return run

    args = dict(core_job_id="job-core", engagement_id="eng-opaque", lease_owner="plan-1",
                environment="devtest", state_root=state_root, template_root=source,
                job_repository=jobs,
                engagement_repository=SimpleNamespace(get=lambda _: records["engagement"]),
                sketch_repository=SimpleNamespace(list_for_engagement=lambda _: records["chains"]),
                plan_repository=SimpleNamespace(get=lambda _: records["core_plan"]),
                credential_repository=records["credential_repository"],
                ssh_key_repository=SimpleNamespace(),
                lease_lookup=lambda _: lease["value"],
                linode_runner=fake_runner("linode"), digitalocean_runner=fake_runner("digitalocean"))
    return SimpleNamespace(args=args, records=records, jobs=jobs, calls=calls,
                           failures=failures, lease=lease, state_root=state_root)


def test_reviewed_order_both_receipts_restart_and_real_regional_ledger(case):
    result = parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    order = [case.records["chains"][i].middle_provider for i in range(2)]
    assert result.status == "running" and result.input["phase"] == "both_plans_saved"
    assert case.calls == order + order
    assert [event.message for event in result.events] == list(parent_service._MESSAGES[:5])
    assert [result.events[2].data["provider"], result.events[3].data["provider"]] == order
    assert [result.events[2].data["chainId"], result.events[3].data["chainId"]] == [
        chain.chain_id for chain in case.records["chains"]]
    assert result.events[4].data["firstReceiptSha256"] == result.events[2].data["receiptSha256"]
    assert result.events[4].data["secondReceiptSha256"] == result.events[3].data["receiptSha256"]
    # A fresh repository instance observes the same parent and the duplicate
    # path revalidates both receipts without another event or provider Apply.
    again = parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    assert again == result and len(again.events) == 5
    assert case.calls == order + order + order
    ledger = json.loads((case.state_root / "eng-opaque/provider-keyed-v2/regional-ordinals.json").read_text())
    assert ledger["us-west"] == 2


def test_seal_both_orders_and_duplicate_uses_historical_snapshot(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    before = len(case.calls)
    sealed = parent_service.seal_mixed_initial_apply(**case.args)
    assert sealed.input["phase"] == "apply_sealed"
    assert len(sealed.events) == 6 and len(case.calls) == before + 2
    data = parent_service.validate_mixed_initial_apply_seal(sealed)
    assert data["orderedProviders"] == [chain.middle_provider for chain in case.records["chains"]]
    assert data["chainIds"] == [chain.chain_id for chain in case.records["chains"]]
    assert data["receiptSha256"] == [sealed.events[2].data["receiptSha256"],
                                     sealed.events[3].data["receiptSha256"]]
    assert set(data["reviewedPolicy"]) == {"linode", "digitalocean"}
    # A future partial state is not recompiled or replanned to recognize this seal.
    case.lease["value"] = ("plan-1", "provider_keyed_teardown_fence")
    assert parent_service.seal_mixed_initial_apply(**case.args) == sealed
    assert parent_service.prepare_or_reuse_mixed_initial_plans(**case.args) == sealed
    assert len(case.calls) == before + 2


def test_seal_rejects_receipt_drift_without_checkpoint(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    provider = case.records["chains"][0].middle_provider
    receipt = case.args[f"{provider if provider == 'linode' else 'digitalocean'}_runner"]
    original = receipt
    def changed(**kwargs):
        value = dict(original(**kwargs))
        value["planSha256"] = "0" * 64
        return value
    case.args[f"{provider}_runner"] = changed
    with pytest.raises(parent_service.MixedInitialPlanParentError, match="plan changed"):
        parent_service.seal_mixed_initial_apply(**case.args)
    assert case.jobs.get(parent_service._parent_id("job-core")).input["phase"] == "both_plans_saved"


def test_seal_rejects_credential_drift_without_checkpoint(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    original = case.args["credential_repository"]
    def get(identifier):
        credential = original.get(identifier)
        return replace(credential, encrypted_secret="changed") if identifier == "cred-do" else credential
    drifted = SimpleNamespace(get=get, get_default=original.get_default)
    with pytest.raises(Exception):
        parent_service.seal_mixed_initial_apply(**{**case.args, "credential_repository": drifted})
    assert len(case.jobs.get(parent_service._parent_id("job-core")).events) == 5


def test_seal_retry_after_crash_before_cas_is_one_checkpoint(case, monkeypatch):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    original = case.jobs.append_mixed_plan_phase_if_claimed
    monkeypatch.setattr(case.jobs, "append_mixed_plan_phase_if_claimed", lambda *a, **kw: None)
    with pytest.raises(parent_service.MixedInitialPlanParentError, match="lost its claim"):
        parent_service.seal_mixed_initial_apply(**case.args)
    current = case.jobs.get(parent_service._parent_id("job-core"))
    assert current.input["phase"] == "both_plans_saved" and len(current.events) == 5
    monkeypatch.setattr(case.jobs, "append_mixed_plan_phase_if_claimed", original)
    with case.jobs._connect() as connection:
        connection.execute("UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', ?) WHERE id = ?",
                           ("2020-01-01T00:00:00+00:00", current.id))
    sealed = parent_service.seal_mixed_initial_apply(**case.args)
    assert sealed.input["phase"] == "apply_sealed" and len(sealed.events) == 6
    assert parent_service.seal_mixed_initial_apply(**case.args) == sealed


def test_historical_seal_recognizes_immutable_prefix_after_future_phase(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    sealed = parent_service.seal_mixed_initial_apply(**case.args)
    future = sealed.__class__(**{**sealed.__dict__, "input": {**sealed.input, "phase": "future_apply"},
                                 "events": [*sealed.events, JobEvent(7, "info", "future", {})]})
    assert parent_service.validate_mixed_initial_apply_seal(future) == sealed.events[5].data


def test_historical_seal_rejects_copied_events_on_alien_parent(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    sealed = parent_service.seal_mixed_initial_apply(**case.args)
    alien = replace(sealed, id="job-alien")
    with pytest.raises(parent_service.MixedInitialPlanParentError):
        parent_service.validate_mixed_initial_apply_seal(alien)
    alien = replace(sealed, target_id="another-engagement")
    with pytest.raises(parent_service.MixedInitialPlanParentError):
        parent_service.validate_mixed_initial_apply_seal(alien)


def test_seal_rejects_lease_change_without_sixth_event(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    case.lease["value"] = ("plan-1", "provider_keyed_teardown_fence")
    with pytest.raises(Exception):
        parent_service.seal_mixed_initial_apply(**case.args)
    assert len(case.jobs.get(parent_service._parent_id("job-core")).events) == 5


def test_second_plan_interruption_preserves_first_checkpoint_for_restart(case):
    order = [chain.middle_provider for chain in case.records["chains"]]
    case.failures["provider"] = order[1]
    with pytest.raises(RuntimeError, match="interrupted"):
        parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    partial = case.jobs.get(parent_service._parent_id("job-core"))
    assert partial.input["phase"] == "first_plan_saved" and len(partial.events) == 3
    # Simulate a dead worker's lease expiring before a new worker resumes.
    with case.jobs._connect() as connection:
        connection.execute("UPDATE job_runs SET input = json_set(input, '$.claimExpiresAt', ?) WHERE id = ?",
                           ("2020-01-01T00:00:00+00:00", partial.id))
    result = parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    assert result.input["phase"] == "both_plans_saved"
    assert len(result.events) == 5 and case.calls.count(order[0]) >= 2


def test_tampered_parent_event_rejects_duplicate(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    prior = case.jobs.get(parent_service._parent_id("job-core"))
    with case.jobs._connect() as connection:
        connection.execute("UPDATE job_events SET data = ? WHERE job_id = ? AND sequence = 3",
                           (json.dumps({"tampered": True}), prior.id))
    with pytest.raises(parent_service.MixedInitialPlanParentError):
        parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)


def test_changed_reviewed_scope_rejects_reuse(case):
    parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    scope = case.records["core_plan"].evidence["sketchAuthorization"]["providerScopes"][0]
    scope["image"] = "changed-after-review"
    with pytest.raises(ValueError):
        parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)


def test_lease_lost_by_last_receipt_reuse_cannot_checkpoint(case):
    provider = case.records["chains"][1].middle_provider
    original = case.args[f"{provider}_runner"]
    calls = 0

    def lose_lease_after_last_reuse(**kwargs):
        nonlocal calls
        receipt = original(**kwargs)
        calls += 1
        if calls == 2:
            case.lease["value"] = None
        return receipt

    case.args[f"{provider}_runner"] = lose_lease_after_last_reuse
    with pytest.raises(ValueError, match="lease"):
        parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    saved = case.jobs.get(parent_service._parent_id("job-core"))
    assert saved.input["phase"] == "second_plan_saved" and len(saved.events) == 4


def test_append_phase_cas_rejects_stale_claim_journal_and_order(case):
    order = [chain.middle_provider for chain in case.records["chains"]]
    case.failures["provider"] = order[1]
    with pytest.raises(RuntimeError, match="interrupted"):
        parent_service.prepare_or_reuse_mixed_initial_plans(**case.args)
    partial = case.jobs.get(parent_service._parent_id("job-core"))
    assert partial.input["phase"] == "first_plan_saved"
    # The valid shape is deliberately independent of adapter execution here.
    digest = hashlib.sha256(b"second receipt").hexdigest()
    event = JobEvent(4, "info", "second mixed provider plan saved",
                     {"provider": order[1], "chainId": case.records["chains"][1].chain_id,
                      "receiptSha256": digest, "planSha256": digest,
                      "journalSha256": digest})
    kwargs = dict(owner=parent_service._OWNER, token=partial.input["claimToken"],
                  lease_owner="plan-1",
                  expected_event_digest=job_event_digest(partial.events),
                  next_phase="second_plan_saved", event=event)
    assert case.jobs.append_mixed_plan_phase_if_claimed(
        partial, **{**kwargs, "token": "wrong"}) is None
    assert case.jobs.append_mixed_plan_phase_if_claimed(
        partial, **{**kwargs, "expected_event_digest": "0" * 64}) is None
    assert case.jobs.append_mixed_plan_phase_if_claimed(
        partial, **{**kwargs, "event": JobEvent(4, "info", event.message,
                                               {**event.data, "provider": order[0]})}) is None
    with case.jobs._connect() as connection:
        connection.execute("UPDATE job_events SET data = ? WHERE job_id = ? AND sequence = 3",
                           (json.dumps({"drift": True}), partial.id))
    assert case.jobs.append_mixed_plan_phase_if_claimed(partial, **kwargs) is None
    current = case.jobs.get(partial.id)
    assert current.input["phase"] == "first_plan_saved" and len(current.events) == 3
