# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted mixed host-contact journal and no-replay behavior."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from types import SimpleNamespace

import pytest

import app.services.provider_keyed_mixed_initial_host_proof as proof
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, ProcessIdentity, StartedCommand,
)
from app.services.provider_keyed_mixed_initial_bootstrap import run_mixed_initial_bootstrap
from app.services.provider_keyed_mixed_strict_host_receipt import (
    MixedStrictHostProofAttention, MixedStrictHostReceipt, child_id,
)
from app.services.sketch_bootstrap import SketchBootstrapCoreHost
from app.storage.job_repository import job_event_digest
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_bootstrap import _inputs
from test_provider_keyed_mixed_initial_plan_parent import case


@dataclass(frozen=True)
class FakeIdentity:
    invocation_id: str


@dataclass(frozen=True)
class FakeCollection:
    identity: FakeIdentity
    commands: tuple[str, str, str]


def _prepared(ready, tmp_path, monkeypatch):
    _checkpoint, _binding, args, _calls, _state = _inputs(ready, tmp_path)
    run_mixed_initial_bootstrap(**args)
    monkeypatch.setattr(proof, "_process_quiescent", lambda *_args: True)
    monkeypatch.setattr(proof, "_core_known_hosts",
                        lambda _core: (str(tmp_path / "core-known-hosts"), "a" * 64))
    monkeypatch.setattr(proof, "_sketch_file_snapshot",
                        lambda _path: (0, 0, "c" * 64))
    monkeypatch.setattr(proof, "_core_hosts", lambda *_a, **_k: (
        SketchBootstrapCoreHost("homebase", "1.1.1.1", "user", "/tmp/identity"),
        SketchBootstrapCoreHost("proxy01", "192.168.2.12", "user", "/tmp/identity", "8.8.8.8"),
    ))
    monkeypatch.setattr(proof, "retrieve_sketch_ssh_key",
                        lambda _eng: SimpleNamespace(public_key="ssh-ed25519 ADMIN"))
    monkeypatch.setattr(proof, "retrieve_sketch_transport_ssh_key",
                        lambda _eng: SimpleNamespace(public_key="ssh-ed25519 TRANSPORT"))
    monkeypatch.setattr(proof, "_key_digest", lambda raw: hashlib.sha256(raw.encode()).hexdigest())
    monkeypatch.setattr(proof, "verify_mixed_strict_host_set",
                        lambda _source, _manifest, _projections, collections, **_kwargs:
                        hashlib.sha256(json.dumps([asdict(c) for c in collections],
                                                  sort_keys=True, separators=(",", ":")).encode()).hexdigest())

    def recognize(source, child, _manifest, _projections, *, evidence_path, **_kwargs):
        return MixedStrictHostReceipt(
            source, child.id, job_event_digest(child.events),
            child.events[-1].data["hostEvidenceSha256"],
            tuple(row.hostname for row in source.host_rows),
            tuple(row.provider_instance_id for row in source.host_rows),
            str(evidence_path), child.input["claimOwner"], child.input["claimToken"],
            "a" * 64, "b" * 64)

    monkeypatch.setattr(proof, "recognize_completed_mixed_initial_strict_host_proof", recognize)
    plan_state = {"current": __import__("dataclasses").replace(
        ready.case.records["core_plan"], stage="applied")}
    plans = SimpleNamespace(get=lambda _plan_id: plan_state["current"], state=plan_state)
    inputs = dict(environment="devtest", job_repository=ready.case.jobs,
                  plan_repository=plans, sketch_repository=args["sketch_repository"],
                  lease_lookup=ready.case.args["lease_lookup"],
                  fresh_observer=args["fresh_observer"])
    return inputs


def _collector(seen, *, stop_at=None, uncertain=False):
    def collect(*, scratch_path, scratch_intent_callback, intent_callback,
                started_callback, heartbeat_callback, result_callback,
                node=None, expected=None, **_kwargs):
        name = node["hostname"] if node is not None else expected.name
        seen.append(name)
        scratch_intent_callback(str(scratch_path) if node is not None
                                else SimpleNamespace(scratch_path=str(scratch_path)))
        invocations = []
        for index in range(4):
            invocation = f"{name}-{index}"
            invocations.append(invocation)
            intent = CommandIntent(invocation, str(scratch_path), "a" * 64)
            intent_callback(intent)
            if stop_at == name and (uncertain or index == 1):
                raise RuntimeError("injected uncertain command")
            started = StartedCommand(intent, ProcessIdentity("boot", 123, 123, 99))
            started_callback(started)
            heartbeat_callback(started)
            result_callback(CommandAuditResult(started, 0, 123, 0, False, False))
        return FakeCollection(FakeIdentity(invocations[0]), tuple(invocations[1:]))
    return collect


@pytest.mark.parametrize("inert_history", [False, True])
def test_four_hosts_leave_claimed_durable_receipt_without_publishing(ready, tmp_path, monkeypatch, inert_history):
    inputs = _prepared(ready, tmp_path, monkeypatch)
    if inert_history:
        original = inputs["sketch_repository"].list_for_engagement("eng-opaque")
        ghost = replace(original[0], chain_id="old-default", status="aborted",
            deploy_job_id="", teardown_job_id="", terraform_working_directory="", nodes=[])
        inputs["sketch_repository"] = SimpleNamespace(list_for_engagement=lambda _: [ghost, *original])
    seen = []
    collect = _collector(seen)
    receipt = proof.collect_mixed_initial_strict_host_proof(
        "eng-opaque", "job-core", **{**inputs, "linode_collector": collect,
                                      "digitalocean_middle_collector": collect,
                                      "digitalocean_edge_collector": collect})
    child = ready.case.jobs.get(child_id("job-core"))
    assert len(seen) == 4 and len(set(seen)) == 4
    assert child.status == "running" and child.finished_at is None
    assert child.events[-1].message == "mixed strict host proof completed"
    assert sum(event.message == "mixed strict host command intended" for event in child.events) == 16
    assert receipt.child_event_sha256 == job_event_digest(child.events)
    assert ready.case.jobs.get(receipt.source.parent_job_id).status == "running"
    assert all(chain.status == "pending" for chain in inputs["sketch_repository"].list_for_engagement("eng-opaque") if chain.chain_id != "old-default")
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof(
            "eng-opaque", "job-core", **{**inputs, "linode_collector": collect,
                                          "digitalocean_middle_collector": collect,
                                          "digitalocean_edge_collector": collect})
    assert len(seen) == 4


def test_real_fresh_observer_receives_stable_generation_fence_before_contact(
        ready, tmp_path, monkeypatch):
    inputs = _prepared(ready, tmp_path, monkeypatch)
    tokens = []

    def check_fence(_parent, _child, _workspace, *, fence, **_kwargs):
        tokens.extend((fence(), fence()))
        if not all(isinstance(token, str) and token for token in tokens):
            raise ValueError("fresh inventory requires a nonempty generation fence")
        raise RuntimeError("stop before provider inventory or host contact")

    monkeypatch.setattr(proof, "prove_mixed_initial_prior_provider_fresh", check_fence)
    contacts = []
    collect = _collector(contacts)
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof(
            "eng-opaque", "job-core", **{**inputs, "fresh_observer": None,
                                          "linode_collector": collect,
                                          "digitalocean_middle_collector": collect,
                                          "digitalocean_edge_collector": collect})
    assert len(tokens) == 2 and tokens[0] == tokens[1]
    assert contacts == []
    assert ready.case.jobs.get(child_id("job-core")) is None


@pytest.mark.parametrize("failed_host_index", [2, 4])
def test_late_host_uncertainty_fences_all_retries(
        ready, tmp_path, monkeypatch, failed_host_index):
    inputs = _prepared(ready, tmp_path, monkeypatch)
    seen = []
    counter = {"value": 0}
    base = _collector(seen)

    def fail_selected(**kwargs):
        counter["value"] += 1
        if counter["value"] == failed_host_index:
            return _collector(seen, stop_at=kwargs.get("node", {}).get("hostname")
                              if kwargs.get("node") is not None else kwargs["expected"].name)(**kwargs)
        return base(**kwargs)

    kwargs = {**inputs, "linode_collector": fail_selected,
              "digitalocean_middle_collector": fail_selected,
              "digitalocean_edge_collector": fail_selected}
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof("eng-opaque", "job-core", **kwargs)
    child = ready.case.jobs.get(child_id("job-core"))
    assert len(seen) == failed_host_index
    assert child is not None and child.status in {"running", "failed"}
    assert sum(event.message == "mixed strict host command intended" for event in child.events) >= (
        failed_host_index - 1) * 4 + 2
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof("eng-opaque", "job-core", **kwargs)
    assert len(seen) == failed_host_index


def test_source_drift_after_reservation_blocks_first_contact(ready, tmp_path, monkeypatch):
    inputs = _prepared(ready, tmp_path, monkeypatch)
    original = inputs["fresh_observer"]
    reads = {"count": 0}

    def drift(parent, provider, fence):
        from dataclasses import replace

        reads["count"] += 1
        result = original(parent, provider, fence)
        if reads["count"] > 2:
            return replace(result, state_json=result.state_json + b" ")
        return result

    contacts = []
    collect = _collector(contacts)
    kwargs = {**inputs, "fresh_observer": drift,
              "linode_collector": collect,
              "digitalocean_middle_collector": collect,
              "digitalocean_edge_collector": collect}
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof("eng-opaque", "job-core", **kwargs)
    assert contacts == []
    assert ready.case.jobs.get(child_id("job-core")) is not None
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof("eng-opaque", "job-core", **kwargs)
    assert contacts == []


def test_reviewed_plan_drift_after_first_host_blocks_further_contact(
        ready, tmp_path, monkeypatch):
    from dataclasses import replace

    inputs = _prepared(ready, tmp_path, monkeypatch)
    seen = []
    base = _collector(seen)

    def change_plan_after_first_contact(**kwargs):
        result = base(**kwargs)
        if len(seen) == 1:
            state = inputs["plan_repository"].state
            state["current"] = replace(state["current"], revision_id="rev-changed")
        return result

    kwargs = {**inputs, "linode_collector": change_plan_after_first_contact,
              "digitalocean_middle_collector": change_plan_after_first_contact,
              "digitalocean_edge_collector": change_plan_after_first_contact}
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof("eng-opaque", "job-core", **kwargs)
    assert len(seen) == 1
    assert ready.case.jobs.get(child_id("job-core")) is not None
    with pytest.raises(MixedStrictHostProofAttention):
        proof.collect_mixed_initial_strict_host_proof("eng-opaque", "job-core", **kwargs)
    assert len(seen) == 1
