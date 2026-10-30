# Copyright (c) 2026, Oracle and/or its affiliates.
"""A restarted append publishes only its already completed new-edge proof."""

from dataclasses import replace
import hashlib
import json
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_append_host_proof_job import (
    _completed_child_receipt, _host_evidence_path,
)
from app.services.provider_keyed_host_binding import _digest_json
from app.services.provider_keyed_host_surface_interpreter import _key_digest
from app.storage.job_repository import SqliteJobRepository, StoredJobRun, job_event_digest
from provider_keyed_append_receipts import strict_edge_raw_fixture
from test_provider_keyed_host_surface_interpreter import _key


NOW = "2026-10-13T00:00:00+00:00"


def _job(id, action, status, input, events):
    return StoredJobRun(id, action, status, "engagement:eng-a", "engagement", "eng-a",
                        "operator", input, [], NOW, NOW,
                        NOW if status == "succeeded" else None, events)


def test_persisted_completed_child_is_sealed_without_recontact(tmp_path, monkeypatch):
    jobs = SqliteJobRepository(tmp_path / "proof.sqlite")
    manifest = {"nodes": ["new-edge"], "stateSha256": "a" * 64}
    terminal = {"newEdgeAddress": "edge-02", "newEdgeProviderId": "9001",
                "stateSha256": "a" * 64}
    evidence_path = _host_evidence_path(tmp_path, "parent")
    raw = strict_edge_raw_fixture(monkeypatch,
        manifest_sha=_digest_json(manifest), chain_id="chain",
        address="edge-02", provider_id="9001", region="region",
        public_ip="198.51.100.3", hostname="edge-host",
        middle_ip="192.0.2.7", admin_public_key=_key(1),
        transport_public_key=_key(2))
    evidence_path.write_bytes(raw)
    evidence_path.chmod(0o600)
    raw_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    parent = jobs.save(_job("parent", "provider_keyed_edge_append", "running", {}, []))
    apply = jobs.save(_job("apply", "provider_keyed_edge_append_apply", "succeeded", {}, []))
    selected = SimpleNamespace(chain_id="chain", nodes=[
        {"publicIp": "192.0.2.7"}, {},
        {"publicIp": "198.51.100.3", "region": "region",
         "hostname": "edge-host"}])
    monkeypatch.setattr("app.services.provider_keyed_append_host_proof_job._proof_context",
        lambda *_args: ("192.0.2.7", {
            "sketch_firewall_v2_enabled": True,
            "sketch_firewall_v2_ssh_sources": ["192.0.2.7/32"],
            "sketch_firewall_v2_rules": [],
        }, _key_digest(_key(1) + "\n"), _key_digest(_key(2) + "\n")))
    entries = [("strict append host proof reserved", {"manifestSha256": _digest_json(manifest)}),
               ("strict append host proof started", {"manifestSha256": _digest_json(manifest)}),
               ("provider append edge contact intended", {
                   "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001"}),]
    for sequence, phase in enumerate(("root_readiness", "root_bootstrap",
                                      "user_readiness", "transport_install"), 1):
        common = {"phase": phase, "sequence": sequence,
                  "newEdgeAddress": "edge-02", "invocationId": phase}
        if phase == "root_bootstrap":
            entries.append(("provider append root bootstrap start fenced", {
                "phase": phase, "sequence": sequence,
                "newEdgeAddress": "edge-02"}))
        entries.extend([
            ("provider append bootstrap command intent fenced", {
                **common, "argvSha256": "a" * 64}),
            ("provider append bootstrap command started before GO", {
                **common, "bootId": "boot", "pid": sequence,
                "pgid": sequence, "startTicks": sequence}),
            ("provider append bootstrap command result fenced", {
                **common, "returnCode": 0}),
        ])
    entries.extend([
        ("provider append new edge bootstrap completed", {
            "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001"}),
        ("strict append host proof scratch intended", {
            "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001",
            "scratchPath": str(tmp_path / "scratch")}),
    ])
    for index, invocation in enumerate(("identity", "before", "surface", "after"), 5):
        entries.extend([
            ("strict append host proof command intended", {
                "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001",
                "invocationId": invocation, "argvSha256": "b" * 64}),
            ("strict append host proof command started before GO", {
                "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001",
                "invocationId": invocation, "bootId": "boot", "pid": index,
                "pgid": index, "startTicks": index}),
            ("strict append host proof command result fenced", {
                "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001",
                "invocationId": invocation, "returnCode": 0}),
        ])
    entries.extend([
        ("strict append host proof capture completed", {
            "newEdgeAddress": "edge-02", "newEdgeProviderId": "9001",
            "hostEvidenceSha256": raw_sha, "hostEvidencePath": str(evidence_path)}),
        ("provider append expanded membership verified", {
            "stateSha256": "a" * 64,
            "providerIds": ["9001", "9002", "9003", "9004", "9005"]}),
        ("strict append host proof completed", {**terminal,
            "hostEvidenceSha256": raw_sha, "hostEvidencePath": str(evidence_path)}),
    ])
    proof = jobs.save(_job("proof", "provider_keyed_edge_append_host_proof", "succeeded",
                           {"parentJobId": parent.id, "applyJobId": apply.id,
                            "mutation": False}, [
        JobEvent(index, "info", message, data)
        for index, (message, data) in enumerate(entries, 1)]))
    assert _completed_child_receipt(jobs.get(proof.id), parent, apply,
                                    _digest_json(manifest), terminal,
                                    evidence_path, selected=selected,
                                    jobs=jobs) == job_event_digest(proof.events)
    assert jobs.get(proof.id) == proof

    for corrupted in (
        replace(proof, input={**proof.input, "mutation": True}),
        replace(proof, events=[replace(proof.events[0], data={"manifestSha256": "0" * 64}),
                               proof.events[1]]),
        replace(proof, events=[proof.events[0], replace(proof.events[1],
            data={**proof.events[1].data, "newEdgeProviderId": "different"})]),
        replace(proof, status="running", finished_at=None),
        replace(proof, events=[replace(event,
            data={key: value for key, value in event.data.items()
                  if key != "argvSha256"})
            if event.message == "provider append bootstrap command intent fenced"
            else event for event in proof.events]),
        replace(proof, events=[replace(event,
            data={key: value for key, value in event.data.items()
                  if key != "pid"})
            if event.message == "strict append host proof command started before GO"
            else event for event in proof.events]),
    ):
        with pytest.raises(ValueError):
            _completed_child_receipt(corrupted, parent, apply, _digest_json(manifest),
                                     terminal, evidence_path, selected=selected,
                                     jobs=jobs)

    with pytest.raises(ValueError):
        _completed_child_receipt(replace(proof, events=[proof.events[0], proof.events[-1]]),
                                 parent, apply, _digest_json(manifest), terminal,
                                 evidence_path, selected=selected, jobs=jobs)
    evidence_path.write_text(json.dumps({
        "identity": {"terraform_address": "edge-02", "provider_instance_id": "9001"},
        "policy_interpreted": False, "firewall_before": {},
        "surface": {}, "firewall_after": {},
    }))
    empty_sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    resealed = replace(proof, events=[
        replace(event, data={**event.data, "hostEvidenceSha256": empty_sha})
        if event.message in {"strict append host proof capture completed",
                             "strict append host proof completed"} else event
        for event in proof.events])
    with pytest.raises(ValueError):
        _completed_child_receipt(resealed, parent, apply, _digest_json(manifest),
                                 terminal, evidence_path, selected=selected, jobs=jobs)
