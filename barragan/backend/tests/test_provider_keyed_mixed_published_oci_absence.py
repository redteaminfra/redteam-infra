# Copyright (c) 2026, Oracle and/or its affiliates.
"""Published OCI absence uses the historical provider handoff after Apply."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.engagement_teardown import _fingerprint
from app.services.provider_keyed_mixed_published_post_oci_source import PublishedMixedPostOciSource
from app.services.provider_keyed_oci_exact_absence import OciAbsencePending
from test_provider_keyed_mixed_initial_apply_child import ready
from test_provider_keyed_mixed_initial_plan_parent import case
from test_provider_keyed_mixed_published_core_preview import _published_go_case
from test_provider_keyed_mixed_zero_apply_core_absence import _absent
import app.services.provider_keyed_mixed_zero_apply_core_apply as apply_service
import app.services.provider_keyed_mixed_zero_apply_core_absence as absence


def _ready(client, ready, tmp_path, monkeypatch):
    source, authority, _, jobs, _, calls, go = _published_go_case(
        client, ready, tmp_path, monkeypatch)
    applied = apply_service.apply_mixed_zero_apply_oci_core_destroy(
        source.engagement_id, source.core_job_id, **go)
    assert applied.status == "succeeded" and calls == ["show", "apply"]
    plan = go["plan_repository"].get(source.core_plan_id)
    old = jobs.get(source.core_job_id)
    sealed = applied.events[5].data
    evidence_sha = _fingerprint(plan.evidence)
    core = jobs.save(replace(old,
        input={**old.input, "corePlanEvidenceSha256": evidence_sha,
               "target": plan.evidence["target"],
               "proxyCount": plan.evidence["proxyCount"],
               "elkEnabled": plan.evidence["elkEnabled"]},
        events=[old.events[0], JobEvent(2, "info", "applied OCI core state sealed", {
            "schema": "applied-oci-core-state-v1",
            "corePlanEvidenceSha256": evidence_sha,
            "rawStateSha256": sealed["preDestroyStateSha256"],
            "inventorySha256": sealed["inventorySha256"],
            "lineage": sealed["lineage"], "serial": sealed["serial"],
            "resourceCount": len(sealed["resourceIds"]),
        }), JobEvent(3, "info", "pilot Standard RTI run finished", {})]))
    state_path = Path(plan.evidence["terraformStatePath"])
    state = json.loads(state_path.read_text())
    state["serial"] += 1
    state["resources"] = []
    state["outputs"] = {}
    state_path.write_text(json.dumps(state))
    monkeypatch.setattr(absence, "_default_state_root", lambda: ready.case.state_root)
    monkeypatch.setattr(absence, "DEFAULT_TERRAFORM_STATE_ROOT", go["core_state_root"])
    monkeypatch.setattr(absence, "_principal_digest", lambda _: "a" * 64)
    post = PublishedMixedPostOciSource(
        authority.core_state_sha256, authority.core_inventory_sha256,
        authority.owned_inspector_record_ids,
        tuple(row.destroy_child_journal_sha256 for row in authority.provider_receipts),
        tuple(row.receipt_sha256 for row in authority.provider_receipts))
    options = dict(
        environment="devtest", state_root=go["state_root"],
        core_state_root=go["core_state_root"], job_repository=jobs,
        plan_repository=go["plan_repository"], lease_lookup=go["lease_lookup"],
        identity_reader=lambda: {}, published=True,
        post_source_reader=lambda *args: post,
        max_scans=2, poll_seconds=0)
    return source, jobs, calls, state_path, options


@pytest.mark.parametrize("pending", [False, True])
def test_published_oci_absence_retries_only_read_only_scans(
        client, ready, tmp_path, monkeypatch, pending):
    with client.application.storage_context():
        source, jobs, calls, state_path, options = _ready(
            client, ready, tmp_path, monkeypatch)
        if pending:
            def slow(_inventory, *, fence, **kwargs):
                fence()
                raise OciAbsencePending("provider is still settling")
            with pytest.raises(absence.MixedZeroApplyCoreAbsenceAttention):
                absence.prove_mixed_zero_apply_oci_core_absence(
                    source.engagement_id, source.core_job_id, **options,
                    absence_prover=slow)
            first = jobs.get(absence._child_prefix(source.core_job_id) + "-attempt-01")
            assert first.status == "failed"
            assert first.events[-1].data == {"retryablePendingTimeout": True}
        result = absence.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=_absent)
        assert result.status == "succeeded"
        assert result.events[-1].data["ociAbsenceWitness"]["phase"] == "absent"
        assert calls == ["show", "apply"]
        assert absence.prove_mixed_zero_apply_oci_core_absence(
            source.engagement_id, source.core_job_id, **options,
            absence_prover=lambda *args, **kwargs: pytest.fail("scan repeated")) == result


def test_published_oci_absence_refuses_nonempty_or_changed_state(
        client, ready, tmp_path, monkeypatch):
    with client.application.storage_context():
        source, jobs, calls, state_path, options = _ready(
            client, ready, tmp_path, monkeypatch)
        state = json.loads(state_path.read_text())
        state["serial"] -= 1
        state_path.write_text(json.dumps(state))
        with pytest.raises(absence.MixedZeroApplyCoreAbsenceAttention):
            absence.prove_mixed_zero_apply_oci_core_absence(
                source.engagement_id, source.core_job_id, **options,
                absence_prover=lambda *args, **kwargs: pytest.fail("OCI scan"))
        assert jobs.get(absence._child_prefix(source.core_job_id) + "-attempt-01") is None
        assert calls == ["show", "apply"]
