# Copyright (c) 2026, Oracle and/or its affiliates.
"""Success-only, no-network post-destroy absence boundary."""

from dataclasses import replace
import hashlib
from datetime import datetime, timezone

import pytest

from app.services import provider_keyed_destroy_absence_preflight as service
from app.services.provider_keyed_digitalocean_absence import DigitalOceanAbsenceEvidence
from app.services import provider_keyed_initial_destroy_apply_job as apply_service
from app.services import provider_keyed_teardown_quiescence as quiescence
from app.domain import JobEvent
from app.storage.job_repository import job_event_digest
from test_provider_keyed_initial_destroy_apply_job import _controller_fixture


def _prepared(tmp_path, monkeypatch):
    jobs, queued, scope, plans, workspace, options, _observed, _commands = (
        _controller_fixture(tmp_path, monkeypatch))
    child = apply_service.run_digitalocean_initial_destroy_apply_job(queued.id, **options)
    assert child.status == "succeeded"
    # Adjacent preview fixture uses an intentionally synthetic retained input
    # digest. The post-destroy reader checks the actual durable file bytes.
    preview = next(row for row in jobs.list() if row.action == service.PLAN_ACTION)
    input_path = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "inputs.json"
    events = list(preview.events)
    events[-1] = replace(events[-1], data={
        **events[-1].data,
        "inputSha256": [[str(input_path), hashlib.sha256(input_path.read_bytes()).hexdigest()]],
    })
    jobs.save(replace(preview, events=events))
    monkeypatch.setattr(service, "_default_state_root", lambda: options["state_root"])
    # The adjacent controller fixture uses synthetic cloud IDs. Real ID shape
    # enforcement is tested in the absence reconciler's focused suite.
    monkeypatch.setattr(service, "_validate_intent", lambda *_args: None)
    pre = child.events[5].data
    proof = DigitalOceanAbsenceEvidence(
        child.events[-1].data["stateSha256"],
        tuple(sorted(value for address, value in pre["resourceIds"].items()
                     if address.startswith("digitalocean_droplet."))),
        pre["resourceIds"]["digitalocean_firewall.firewall"],
        pre["resourceIds"]["digitalocean_ssh_key.key"], True, 2,
    )
    calls = []

    def reconcile(workspace_arg, intent, **kwargs):
        calls.append((workspace_arg, intent, kwargs))
        return proof

    args = dict(
        environment="devtest", state_root=options["state_root"],
        job_repository=jobs, plan_repository=plans,
        sketch_repository=options["sketch_repository"],
        credential_repository=options["credential_repository"],
        lease_lookup=options["lease_lookup"],
        credential_check=lambda *_args: (pre["credentialSecretSha256"],
                                         pre["credentialUpdatedAt"], "encrypted"),
        absence_reconciler=reconcile,
    )
    return jobs, queued, scope, plans, workspace, child, proof, calls, args


def test_successful_destroy_requires_absence_then_returns_tag_pending(tmp_path, monkeypatch):
    jobs, queued, scope, plans, workspace, child, proof, calls, args = _prepared(
        tmp_path, monkeypatch)
    before = jobs.list()
    result = service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args)
    assert result == proof and result.selector_tag_cleanup_pending
    assert len(calls) == 1
    assert calls[0][1].resource_ids == {
        row["address"]: row["id"] for row in scope["resources"]}
    assert calls[0][2]["deployment_target"] == "barragan-testing"
    assert jobs.list() == before
    assert plans.lease == (scope["corePlanId"], "provider_keyed_teardown_fence")


def test_team_readable_terraform_state_is_accepted(tmp_path, monkeypatch):
    _jobs, queued, _scope, _plans, workspace, _child, proof, _calls, args = _prepared(
        tmp_path, monkeypatch)
    workspace.state_path.chmod(0o644)
    assert service.reconcile_successful_digitalocean_destroy_absence(
        queued.id, **args) == proof


def test_exact_precommand_apply_recovery_journal_reaches_absence_only_once(
    tmp_path, monkeypatch,
):
    jobs, queued, _scope, _plans, workspace, child, proof, _calls, args = _prepared(
        tmp_path, monkeypatch)
    failed = [JobEvent(1, "info", "provider destroy apply queued", {}),
              JobEvent(2, "info", "provider destroy apply started", {}),
              JobEvent(3, "error", "provider destroy apply stopped", {})]
    recovery = JobEvent(4, "info", apply_service._PRECOMMAND_APPLY_RECOVERY, {
        "failedJournalSha256": job_event_digest(failed),
        "failedFinishedAt": datetime.now(timezone.utc).isoformat(),
    })
    events = [*failed, recovery,
              *[replace(row, sequence=index) for index, row in enumerate(child.events[2:], 5)]]
    recovered = jobs.save(replace(child, events=events))
    assert len(recovered.events) == 14
    assert service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args) == proof
    wrong = list(events)
    wrong[3] = replace(recovery, data={**recovery.data, "failedJournalSha256": "0" * 64})
    for altered in (wrong, [*events, JobEvent(15, "info", "unexpected", {})]):
        jobs.save(replace(recovered, events=altered))
        with pytest.raises(service.ProviderKeyedDestroyAbsencePreflightError):
            service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args)


def _recovered_child(jobs, child, scope, monkeypatch):
    """Synthesize the incident suffix; keep the ordinary fixture's real authority."""
    prefix = list(child.events[:9])
    original_digest = job_event_digest(prefix)
    monkeypatch.setattr(service, "_RECOVERY_ORIGINAL_JOURNAL_SHA256", original_digest)
    monkeypatch.setattr(quiescence, "_INCIDENT_DESTROY_CHILD", child.id)
    monkeypatch.setattr(quiescence, "_INCIDENT_DESTROY_CHILDREN", frozenset({child.id}))
    def copy_command(index, invocation):
        result = []
        for old in child.events[index:index + 3]:
            result.append(replace(old, data={**old.data, "invocationId": invocation}))
        return result
    suffix = [replace(child.events[0], message="provider destroy pre-GO recovery intended",
                      data={
                          "historicalRevision": service._RECOVERY_REVISION,
                          "originalJournalSha256": original_digest,
                          "planSha256": child.input["planSha256"],
                      })]
    suffix += copy_command(2, "recovered-show")
    suffix += copy_command(7, "recovered-apply")
    suffix += [child.events[10], child.events[11]]
    events = [*prefix, *(replace(event, sequence=index)
                         for index, event in enumerate(suffix, 10))]
    recovered = jobs.save(replace(child, events=events))
    return recovered


def test_exact_recovered_destroy_journal_reaches_existing_absence_proof(tmp_path, monkeypatch):
    jobs, queued, scope, _plans, workspace, child, proof, calls, args = _prepared(
        tmp_path, monkeypatch)
    recovered = _recovered_child(jobs, child, scope, monkeypatch)
    assert quiescence._valid_recovered_destroy_journal(
        jobs, recovered, workspace.path, proof.empty_state_sha256)
    assert service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args) == proof
    assert len(calls) == 1


def test_second_incident_success_journal_requires_its_own_digest_and_revision(
    tmp_path, monkeypatch,
):
    jobs, _queued, _scope, _plans, workspace, child, _proof, _calls, _args = _prepared(
        tmp_path, monkeypatch)
    recovered = _recovered_child(jobs, child, _scope, monkeypatch)
    second_id = "job-provider-keyed-initial-destroy-apply-b4f1bceb4a7d"
    digest = job_event_digest(recovered.events[:9])
    monkeypatch.setattr(service, "_RECOVERY_INCIDENT_JOURNALS", {
        **service._RECOVERY_INCIDENT_JOURNALS, second_id: digest,
    })
    events = list(recovered.events)
    events[9] = replace(events[9], data={**events[9].data,
        "historicalRevision": service._RECOVERY_INCIDENT_REVISIONS[second_id]})
    preview = next(row for row in jobs.list() if row.action == service.PLAN_ACTION)
    binary = preview.events[-1].data["terraformBinaryPath"]
    plan_path = workspace.path / ".barragan-initial-destroy.tfplan"
    assert service._successful_journal(events, binary, plan_path, second_id) == (16, 17)
    for drift in (
        replace(events[9], data={**events[9].data, "historicalRevision": service._RECOVERY_REVISION}),
        replace(events[9], data={**events[9].data, "originalJournalSha256": "0" * 64}),
    ):
        wrong = [*events[:9], drift, *events[10:]]
        with pytest.raises(ValueError):
            service._successful_journal(wrong, binary, plan_path, second_id)
    with pytest.raises(ValueError):
        service._successful_journal(events, binary, plan_path, child.id)


@pytest.mark.parametrize("drift", [
    "partial", "extra", "prefix", "revision", "original_digest", "plan_digest",
    "old_argv", "old_invocation", "show_argv", "apply_argv", "reuse_old_invocation",
    "reuse_new_invocation", "result", "phase", "terminal",
])
def test_recovered_destroy_drift_never_reaches_provider_get(tmp_path, monkeypatch, drift):
    jobs, queued, scope, _plans, workspace, child, proof, calls, args = _prepared(
        tmp_path, monkeypatch)
    recovered = _recovered_child(jobs, child, scope, monkeypatch)
    events = list(recovered.events)
    if drift == "partial":
        events.pop()
    elif drift == "extra":
        events.append(replace(events[-1], sequence=19))
    else:
        index = {
            "prefix": 5, "revision": 9, "original_digest": 9, "plan_digest": 9,
            "old_argv": 7, "old_invocation": 7, "show_argv": 10,
            "apply_argv": 13, "reuse_old_invocation": 10,
            "reuse_new_invocation": 13, "result": 15, "phase": 16,
            "terminal": 17,
        }[drift]
        data = dict(events[index].data)
        if drift == "prefix":
            data["preDestroySerial"] += 1
        elif drift == "revision":
            data["historicalRevision"] = "0" * 40
        elif drift == "original_digest":
            data["originalJournalSha256"] = "0" * 64
        elif drift == "plan_digest":
            data["planSha256"] = "0" * 64
        elif drift in {"old_argv", "show_argv", "apply_argv"}:
            data["argvSha256"] = "0" * 64
        elif drift == "old_invocation":
            data["invocationId"] = ""
        elif drift == "reuse_old_invocation":
            data["invocationId"] = events[2].data["invocationId"]
            for sequence in (11, 12):
                events[sequence] = replace(events[sequence], data={
                    **events[sequence].data, "invocationId": data["invocationId"]})
        elif drift == "reuse_new_invocation":
            data["invocationId"] = events[10].data["invocationId"]
            for sequence in (14, 15):
                events[sequence] = replace(events[sequence], data={
                    **events[sequence].data, "invocationId": data["invocationId"]})
        elif drift == "result":
            data["returnCode"] = 1
        elif drift == "phase":
            data["phase"] = "destroy_started"
        else:
            data["stateSha256"] = "0" * 64
        events[index] = replace(events[index], data=data)
    drifted = jobs.save(replace(recovered, events=events))
    assert not quiescence._valid_recovered_destroy_journal(
        jobs, drifted, workspace.path, proof.empty_state_sha256)
    with pytest.raises(service.ProviderKeyedDestroyAbsencePreflightError):
        service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args)
    assert calls == []


def test_retired_published_selector_cannot_be_used_for_pending_parent(tmp_path, monkeypatch):
    _jobs, queued, _scope, _plans, _workspace, _child, _proof, calls, args = _prepared(
        tmp_path, monkeypatch)
    with pytest.raises(service.ProviderKeyedDestroyAbsencePreflightError):
        service.reconcile_successful_digitalocean_destroy_absence(
            queued.id, **args, retired_published=True)
    assert calls == []


@pytest.mark.parametrize("drift", [
    "running", "extra_child", "prestate_ids", "prestate_lineage", "prestate_dns", "journal_argv",
    "state", "phase", "lease", "parent", "credential", "preview_journal",
    "preview_public", "preview_input", "state_mode",
])
def test_incomplete_or_drifted_destroy_never_reaches_get(tmp_path, monkeypatch, drift):
    jobs, queued, scope, plans, workspace, child, _proof, calls, args = _prepared(
        tmp_path, monkeypatch)
    if drift == "running":
        jobs.save(replace(child, status="running", finished_at=None))
    elif drift == "extra_child":
        jobs.save(replace(child, id="another-destroy-apply"))
    elif drift in {"prestate_ids", "prestate_lineage", "prestate_dns", "journal_argv"}:
        events = list(child.events)
        index = {"prestate_ids": 5, "prestate_lineage": 5,
                 "prestate_dns": 5, "journal_argv": 2}[drift]
        data = dict(events[index].data)
        if drift == "prestate_ids":
            data["resourceIds"] = {**data["resourceIds"],
                                   "digitalocean_firewall.firewall": "other"}
        elif drift == "prestate_lineage":
            data["stateLineage"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        elif drift == "prestate_dns":
            data["dnsCleanupCheckpointSha256"] = "0" * 64
        else:
            data["argvSha256"] = "0" * 64
        events[index] = replace(events[index], data=data)
        jobs.save(replace(child, events=events))
    elif drift == "state":
        workspace.state_path.write_text("{}")
    elif drift == "state_mode":
        workspace.state_path.chmod(0o666)
    elif drift == "phase":
        (workspace.path / ".barragan-apply-phase.json").write_text("{}")
    elif drift == "preview_journal":
        preview = next(row for row in jobs.list() if row.action == service.PLAN_ACTION)
        events = list(preview.events)
        events[3] = replace(events[3], data={**events[3].data, "argvSha256": "0" * 64})
        jobs.save(replace(preview, events=events))
    elif drift == "preview_public":
        preview = next(row for row in jobs.list() if row.action == service.PLAN_ACTION)
        events = list(preview.events)
        events[2] = replace(events[2], data={
            **events[2].data, "publicKeyPath": str(workspace.path / "other-public")})
        jobs.save(replace(preview, events=events))
    elif drift == "preview_input":
        input_path = workspace.path.parents[1] / ".plan-material" / "digitalocean" / "inputs.json"
        input_path.write_text("changed")
    elif drift == "lease":
        plans.lease = (scope["corePlanId"], "wrong-operation")
    elif drift == "parent":
        jobs.save(replace(queued, input={**queued.input, "phase": "attention"}))
    else:
        args["credential_check"] = lambda *_a: ("0" * 64, "changed", "encrypted")
    with pytest.raises(service.ProviderKeyedDestroyAbsencePreflightError):
        service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args)
    assert calls == []


def test_authority_change_during_provider_get_fails_after_get(tmp_path, monkeypatch):
    jobs, queued, scope, plans, workspace, child, proof, calls, args = _prepared(
        tmp_path, monkeypatch)

    def drift(*_args, **_kwargs):
        plans.lease = (scope["corePlanId"], "wrong-operation")
        return proof

    args["absence_reconciler"] = drift
    with pytest.raises(service.ProviderKeyedDestroyAbsencePreflightError):
        service.reconcile_successful_digitalocean_destroy_absence(queued.id, **args)
