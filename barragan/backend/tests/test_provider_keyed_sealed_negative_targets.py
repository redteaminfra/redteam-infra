# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact sealed target syntax through the real negative service, offline.

Upstream source, core-absence and Inspector observations are explicit fixture
seams. The real scope reconstruction, negative writer/classifier and no-probe
failure behavior remain active; Linux composition supplies full authority proof.
"""
from copy import deepcopy
from dataclasses import replace

import pytest

from app.services import engagement_teardown as teardown
from app.services import provider_keyed_inspector_negative as negative
from app.services import provider_keyed_published_initial_cleanup_authority as cleanup
from test_provider_keyed_published_teardown_reservation import _sealed_case
from test_provider_keyed_inspector_negative import _case


def _scope(client, monkeypatch, tmp_path):
    with client.application.storage_context():
        _jobs, proposal, _source = _sealed_case(client, monkeypatch, tmp_path)
        return deepcopy(proposal.input["scopeSnapshot"])


def test_shared_scope_adapter_preserves_exact_sealed_and_legacy_targets(client, monkeypatch, tmp_path):
    scope = _scope(client, monkeypatch, tmp_path)
    before = deepcopy(scope)
    assert teardown._valid_public_targets(scope["publicVerificationTargets"]) is False
    assert teardown._valid_scope_public_targets(scope) is True
    assert scope == before
    legacy = {"publicVerificationTargets": [row for row in scope["publicVerificationTargets"]
        if row.get("targetGroup") == "core-public-management"]}
    assert teardown._valid_scope_public_targets(legacy) == teardown._valid_public_targets(legacy["publicVerificationTargets"])
    for malformed in (None, [], {}, {"publicVerificationTargets": None}):
        assert teardown._valid_scope_public_targets(malformed) is False


@pytest.mark.parametrize("drift", [None, "missing_seal", "hash", "group", "foreign_host", "outer_rehashed_target", "omitted", "extra"])
def test_real_negative_service_uses_sealed_scope_before_reservation(client, monkeypatch, tmp_path, drift):
    scope = _scope(client, monkeypatch, tmp_path)
    parent, snapshot, _settings, _record, calls, options = _case(tmp_path, monkeypatch)
    jobs = options["job_repository"]
    inspector = snapshot["inspector"]
    snapshot.clear(); snapshot.update(scope)
    snapshot["inspector"] = {**inspector, "verificationTargetCount": len(scope["publicVerificationTargets"])}
    jobs.save(replace(parent, input={**parent.input, "publishedSource": {"example": True}}))
    coordinator = jobs.get(negative._child_id("job-core"))
    jobs.save(replace(coordinator, input={**coordinator.input, "phase": "group_retired"}))
    absence_id = "job-provider-keyed-core-destroy-absence-core-attempt-01"
    absence = jobs.get(absence_id)
    jobs.save(replace(absence, input={**absence.input, "scopeSnapshotId": snapshot["snapshotId"]}))
    # These existing receipt/source boundaries are deliberately outside this
    # target-adapter fixture. Do not mistake them for composed source proof.
    monkeypatch.setattr(negative, "recognize_provider_keyed_group_retired", lambda *_a, **_k: ("one", "two"))
    monkeypatch.setattr(negative, "prove_pending_keyed_oci_core_destroy_absence", lambda *_a, **_k: jobs.get(absence_id))
    source_checks = []
    monkeypatch.setattr(cleanup, "validate_saved_cleanup", lambda *_a: source_checks.append(True))
    options["positive_control"] = {"id": "inspector-external-control", "type": "tcp", "host": "4.2.2.2", "port": 443}
    if drift == "missing_seal":
        snapshot.pop(cleanup.KEY)
    elif drift == "hash":
        snapshot[cleanup.KEY]["sha256"] = "0" * 64
    elif drift == "group":
        snapshot["publicVerificationTargets"][-1]["targetGroup"] = "foreign-group"
    elif drift in {"foreign_host", "outer_rehashed_target"}:
        snapshot["publicVerificationTargets"][-1]["host"] = "8.8.4.4"
        if drift == "outer_rehashed_target":
            seal = snapshot[cleanup.KEY]
            seal["sha256"] = cleanup.digest({key: value for key, value in seal.items() if key != "sha256"})
    elif drift == "omitted":
        snapshot["publicVerificationTargets"].pop()
        snapshot["inspector"]["verificationTargetCount"] -= 1
    elif drift == "extra":
        snapshot["publicVerificationTargets"].append({"id": "tcp:8.8.4.4:80", "type": "tcp-forbidden", "host": "8.8.4.4", "port": 80})
        snapshot["inspector"]["verificationTargetCount"] += 1
    original = deepcopy(snapshot)
    if drift is None:
        result = negative.prove_pending_keyed_inspector_negative(parent.id, **options)
        assert result.status == "succeeded" and len(calls) == 2 and source_checks
        assert calls[0][2]["negative"] == snapshot["publicVerificationTargets"]
    else:
        with pytest.raises(negative.KeyedInspectorNegativeAttention):
            negative.prove_pending_keyed_inspector_negative(parent.id, **options)
        assert calls == [] and jobs.get("job-provider-keyed-inspector-negative-core") is None
        assert source_checks == []
    assert snapshot == original
