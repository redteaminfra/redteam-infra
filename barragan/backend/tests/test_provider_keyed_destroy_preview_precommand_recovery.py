# Copyright (c) 2026, Oracle and/or its affiliates.
"""Exact, append-only recovery of a failed destroy preview before Terraform contact."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_append_source import audit_published_provider_keyed_append_source
from app.services.provider_keyed_initial_destroy_plan_job import (
    _PRECOMMAND_RECOVERY, _precommand_failed_preview,
)
from app.storage.job_repository import SqlAlchemyJobRepository, job_event_digest
from test_provider_keyed_append_source import _case, _reviewed_append_parent
from test_provider_keyed_initial_destroy_apply_job import _proved_preview
from app.services.provider_keyed_initial_destroy_apply_job import _audit_completed_preview_journal
from app.services import provider_keyed_destroy_absence_preflight as absence_preflight
from app.services import provider_keyed_initial_destroy_pre_go_recovery as pre_go_recovery


def test_persisted_failed_precommand_child_rearms_once_after_quiescence(client, tmp_path, monkeypatch):
    with client.application.storage_context():
        core_id, engagement_id, _state_sha, _added = _case(client, tmp_path, monkeypatch)
        jobs, proposal = _reviewed_append_parent(core_id, engagement_id, tmp_path)
        source = audit_published_provider_keyed_append_source(core_id, state_root=tmp_path)
        parent = jobs.reserve_published_keyed_append_teardown_parent(
            proposal, reviewed_source=source, state_root=tmp_path)
        core = jobs.get(core_id)
        snapshot = parent.input["scopeSnapshot"]
        root = tmp_path / "provider"
        input_path = root.parents[1] / ".plan-material" / "digitalocean" / "append-inputs.json"
        stage = root / (".barragan-destroy-inputs-" + "a" * 32)
        instant = datetime.now(timezone.utc)
        child = jobs.save(replace(
            core, id="job-provider-keyed-initial-destroy-plan-core",
            action="provider_keyed_initial_destroy_plan", status="failed",
            target=f"engagement:{engagement_id}", target_type="engagement",
            target_id=engagement_id,
            input={"engagementId": engagement_id, "coreJobId": core_id,
                   "corePlanId": source.initial_source.core_plan_id,
                   "teardownParentId": parent.id,
                   "scopeSnapshotId": snapshot["snapshotId"],
                   "providerScopeSha256": snapshot["providerScopeSha256"],
                   "mutation": True}, artifact_refs=[],
            created_at=(instant - timedelta(minutes=4)).isoformat(),
            started_at=(instant - timedelta(minutes=3)).isoformat(),
            finished_at=(instant - timedelta(minutes=2)).isoformat(),
            events=[
                JobEvent(1, "info", "provider destroy preview queued", {}),
                JobEvent(2, "info", "provider destroy preview started", {}),
                JobEvent(3, "info", "provider destroy preview staging intended", {
                    "publicKeyPath": str(input_path.parent / "admin-public"),
                    "stagingPath": str(stage),
                    "stagedInputPath": str(stage / "input-0.json"),
                    "credentialPath": str(stage / "credential.json"),
                    "planPath": str(root / ".barragan-initial-destroy.tfplan"),
                }),
                JobEvent(4, "error", "provider destroy preview stopped; reconciliation required",
                         {"failureStage": "other"}),
            ],
        ))
        assert not _precommand_failed_preview(
            replace(child, finished_at=instant.isoformat()), parent, core, snapshot,
            root, input_path)
        stage.mkdir()
        assert not _precommand_failed_preview(child, parent, core, snapshot, root, input_path)
        stage.rmdir()
        assert _precommand_failed_preview(child, parent, core, snapshot, root, input_path)
        original = list(child.events)

        def authority():
            return (_precommand_failed_preview(jobs.get(child.id), parent, core, snapshot,
                                               root, input_path)
                    and jobs.get(parent.id) == parent)

        claimed_at = datetime.now(timezone.utc)
        claim = dict(owner="provider-keyed-destroy-preview-" + "a" * 32,
                     token="b" * 32, claimed_at=claimed_at.isoformat(),
                     expires_at=(claimed_at + timedelta(minutes=1)).isoformat())
        rearmed = jobs.rearm_exact_precommand_destroy_preview(
            child, authority=authority, **claim)
        assert rearmed is not None and rearmed.status == "running"
        assert rearmed.finished_at is None and rearmed.events[:4] == original
        assert rearmed.input["claimToken"] == claim["token"]
        assert rearmed.events[4] == JobEvent(
            5, "info", _PRECOMMAND_RECOVERY,
            {"failedJournalSha256": job_event_digest(original),
             "failedFinishedAt": child.finished_at})
        assert jobs.rearm_exact_precommand_destroy_preview(
            child, authority=authority, **claim) is None
        assert jobs.get(child.id) == rearmed
def test_apply_parser_accepts_only_exact_recovered_prefix(tmp_path, monkeypatch):
    jobs, _parent, _scope, _plans, workspace, preview, _options, _observed = (
        _proved_preview(tmp_path, monkeypatch))
    normal = list(preview.events)
    old = dict(normal[2].data)
    original_stage = Path(old["stagingPath"])
    prior_stage = original_stage.with_name(".barragan-destroy-inputs-" + "a" * 32)
    old.update(stagingPath=str(prior_stage),
               stagedInputPath=str(prior_stage / Path(old["stagedInputPath"]).name),
               credentialPath=str(prior_stage / "credential.json"))
    prefix = [normal[0], normal[1], JobEvent(3, "info", normal[2].message, old),
              JobEvent(4, "error", "provider destroy preview stopped; reconciliation required",
                       {"failureStage": "other"})]
    marker = JobEvent(5, "info", _PRECOMMAND_RECOVERY,
                      {"failedJournalSha256": job_event_digest(prefix),
                       "failedFinishedAt": "2026-10-14T00:00:00+00:00"})
    events = [*prefix, marker,
              *[replace(row, sequence=index) for index, row in enumerate(normal[2:], 6)]]
    recovered = replace(preview, events=events)
    evidence = {"inputSha256": normal[-1].data["inputSha256"],
                "adminPublicKeyPath": old["publicKeyPath"]}
    _audit_completed_preview_journal(recovered, workspace, evidence,
                                     Path(normal[-1].data["planPath"]))
    # Both downstream preflight readers import the shared entry point. A
    # recovered preview must remain auditable after apply, including on the
    # reviewed pre-GO recovery path.
    for reader in (absence_preflight, pre_go_recovery):
        reader._audit_successful_preview_journal(
            recovered, workspace, evidence, Path(normal[-1].data["planPath"]))
    wrong = list(events)
    wrong[4] = replace(marker, data={"failedJournalSha256": "0" * 64})
    with pytest.raises(ValueError):
        _audit_completed_preview_journal(replace(recovered, events=wrong), workspace,
                                         evidence, Path(normal[-1].data["planPath"]))
    extra = replace(recovered, events=[*events, JobEvent(20, "info", "unexpected", {})])
    for reader in (absence_preflight, pre_go_recovery):
        with pytest.raises(ValueError):
            reader._audit_successful_preview_journal(
                extra, workspace, evidence, Path(normal[-1].data["planPath"]))
