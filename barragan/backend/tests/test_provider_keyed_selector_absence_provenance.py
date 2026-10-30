# Copyright (c) 2026, Oracle and/or its affiliates.
"""The initial selector-absence observation must be fenced before apply GO."""

from dataclasses import replace

import pytest

from app.services.provider_keyed_selector_preflight import SelectorPreflightEvidence
import app.services.provider_keyed_initial_apply as low_level
import app.services.provider_keyed_initial_apply_job as job_service
from app.domain import JobEvent
from test_provider_keyed_initial_apply import prepared as direct_prepared
from test_provider_keyed_initial_apply_job import prepared as job_prepared


def test_real_apply_boundary_calls_back_after_fresh_account_scan_before_go(direct_prepared, monkeypatch):
    workspace, plan, kwargs, _, runner, _, _ = direct_prepared
    checked = []
    evidence = SelectorPreflightEvidence(3, 4, 5)
    monkeypatch.setattr(low_level, "require_new_digitalocean_selector_available",
                        lambda *a, **kw: checked.append("account-scan") or evidence)

    def journal(value):
        checked.append(("journal", value))
        assert [args[1] for args, _, _ in runner.calls] == ["show"]

    kwargs["selector_absence_callback"] = journal
    low_level.apply_digitalocean_keyed_initial_saved_plan(workspace, plan, **kwargs)
    assert checked == ["account-scan", ("journal", evidence)]
    assert [args[1] for args, _, _ in runner.calls] == ["show", "apply"]


def test_failed_or_unproved_account_scan_cannot_release_apply_go(direct_prepared, monkeypatch):
    workspace, plan, kwargs, _, runner, _, _ = direct_prepared
    kwargs["selector_absence_callback"] = lambda _: (_ for _ in ()).throw(ValueError("journal failed"))
    monkeypatch.setattr(low_level, "require_new_digitalocean_selector_available",
                        lambda *a, **kw: SelectorPreflightEvidence(0, 0, 0))
    with pytest.raises(low_level.ProviderKeyedInitialApplyError):
        low_level.apply_digitalocean_keyed_initial_saved_plan(workspace, plan, **kwargs)
    assert [args[1] for args, _, _ in runner.calls] == ["show"]
    assert not (workspace.path / ".barragan-apply-phase.json").exists()


def test_claimed_job_persists_selector_absence_and_binds_apply_invocation(job_prepared):
    kwargs, jobs, _, _, intent, decoded = job_prepared
    def applied(*args, **fields):
        # Exercise the real callback ordering used by the lower apply helper.
        shown = fields["command_runner"](["/usr/bin/terraform", "show", "-json",
                                          str(decoded.apply_evidence.plan_path)], args[0].path, {})
        assert shown.returncode == 0
        fields["selector_absence_callback"](SelectorPreflightEvidence(2, 3, 4))
        fields["selector_reservation_callback"]()
        fields["command_runner"](["/usr/bin/terraform", "apply", "-input=false", "-lock=true",
                                  "-no-color", str(decoded.apply_evidence.plan_path)], args[0].path, {})
        return type("Result", (), {"state_sha256": "2" * 64, "selector": intent.selector_tag,
                                   "attachment_proof_pending": True})()

    kwargs["apply"] = applied
    completed = job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    proof = [event for event in completed.events if event.message == "provider selector absent before initial apply"]
    assert len(proof) == 1
    assert proof[0].data["providerConnectionId"] == "connection"
    assert proof[0].data["credentialSecretSha256"] == decoded.apply_evidence.credential_secret_sha256
    assert proof[0].data["selectorTag"] == intent.selector_tag
    assert (proof[0].data["tagsChecked"], proof[0].data["firewallsChecked"],
            proof[0].data["dropletsChecked"]) == (2, 3, 4)
    apply_intent = [event for event in completed.events
                    if event.message == "provider apply command intent fenced" and event.data["phase"] == "apply"]
    assert len(apply_intent) == 1
    assert apply_intent[0].data["selectorAbsenceEventSequence"] == proof[0].sequence
    assert proof[0].sequence < apply_intent[0].sequence
    assert "encrypted-token" not in str(completed.events)
    assert "claimToken" not in str(completed.events)
    job_service.require_initial_selector_absence_provenance(
        completed, engagement_id="eng-opaque", core_job_id="core-job", core_plan_id="core-plan",
        plan_job_id="plan-job", connection_id="connection",
        credential_secret_sha256=decoded.apply_evidence.credential_secret_sha256,
        credential_updated_at=decoded.apply_evidence.credential_updated_at,
        selector_tag=intent.selector_tag, source_sha256="source",
        plan_sha256=decoded.apply_evidence.plan_sha256,
        plan_path=decoded.apply_evidence.plan_path,
        terraform_binary_path=decoded.apply_evidence.terraform_binary_path,
        terraform_binary_sha256=decoded.apply_evidence.terraform_binary_sha256,
    )


@pytest.mark.parametrize("drift", [
    "selector", "credential", "claim", "invocation", "return_code", "status",
    "apply_argv", "show_argv", "show_result", "terminal", "extra_key", "level",
    "receipt_status", "receipt_selector", "intent_claim", "receipt_sequence",
])
def test_persisted_provenance_reader_rejects_drift(job_prepared, drift):
    kwargs, jobs, _, _, intent, decoded = job_prepared
    original_apply = kwargs["apply"]

    def applied(*args, **fields):
        original_apply(*args, **fields)
        return type("Result", (), {"state_sha256": "2" * 64, "selector": intent.selector_tag,
                                   "attachment_proof_pending": True})()

    kwargs["apply"] = applied
    complete = job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    events = list(complete.events)
    if drift == "status":
        complete = replace(complete, status="failed")
    else:
        if drift in {"invocation", "return_code"}:
            target, phase = "provider apply command result fenced", "apply"
        elif drift == "apply_argv":
            target, phase = "provider apply command intent fenced", "apply"
        elif drift == "show_argv":
            target, phase = "provider apply command intent fenced", "show"
        elif drift == "show_result":
            target, phase = "provider apply command result fenced", "show"
        elif drift == "terminal":
            target, phase = "provider saved-plan apply completed; proof pending", None
        elif drift in {"receipt_status", "receipt_selector", "receipt_sequence"}:
            target, phase = "provider selector creation 201 received", None
        elif drift == "intent_claim":
            target, phase = "provider selector creation POST intended", None
        else:
            target, phase = "provider selector absent before initial apply", None
        index = next(i for i, event in enumerate(events)
                     if event.message == target and (phase is None or event.data.get("phase") == phase))
        data = dict(events[index].data)
        if drift == "selector":
            data["selectorTag"] = "other-selector"
        elif drift == "credential":
            data["credentialSecretSha256"] = "0" * 64
        elif drift == "claim":
            data["claimGenerationSha256"] = "invalid"
        elif drift == "invocation":
            data["invocationId"] = "different"
        elif drift in {"apply_argv", "show_argv"}:
            data["argvSha256"] = "0" * 64
        elif drift == "show_result":
            data["returnCode"] = 1
        elif drift == "terminal":
            data["attachmentProofPending"] = False
        elif drift == "receipt_status":
            data["httpStatus"] = 200
        elif drift == "receipt_selector":
            data["selectorTag"] = "other-selector"
        elif drift == "receipt_sequence":
            data["selectorIntentEventSequence"] = 0
        elif drift == "intent_claim":
            data["claimGenerationSha256"] = "0" * 64
        elif drift == "extra_key":
            data["claimToken"] = "leaked"
        elif drift == "level":
            pass
        else:
            data["returnCode"] = 1
        events[index] = JobEvent(events[index].sequence, "error" if drift == "level"
                                 else events[index].level, events[index].message, data)
        complete = replace(complete, events=events)
    with pytest.raises(job_service.ProviderKeyedInitialApplyJobError, match="provenance"):
        job_service.require_initial_selector_absence_provenance(
            complete, engagement_id="eng-opaque", core_job_id="core-job", core_plan_id="core-plan",
            plan_job_id="plan-job", connection_id="connection",
            credential_secret_sha256=decoded.apply_evidence.credential_secret_sha256,
            credential_updated_at=decoded.apply_evidence.credential_updated_at,
            selector_tag=intent.selector_tag, source_sha256="source",
            plan_sha256=decoded.apply_evidence.plan_sha256,
            plan_path=decoded.apply_evidence.plan_path,
            terraform_binary_path=decoded.apply_evidence.terraform_binary_path,
            terraform_binary_sha256=decoded.apply_evidence.terraform_binary_sha256,
        )


def test_claim_drift_at_absence_journal_blocks_apply_go(job_prepared):
    kwargs, jobs, _, _, _, _ = job_prepared
    gate_calls = []

    def applied(workspace, evidence, **fields):
        fields["command_runner"](["/usr/bin/terraform", "show", "-json", str(evidence.plan_path)],
                                 workspace.path, {})
        jobs.current = replace(jobs.current, input={**jobs.current.input, "claimToken": "lost"})
        fields["selector_absence_callback"](SelectorPreflightEvidence(0, 0, 0))
        raise AssertionError("unreachable")

    original_gate = kwargs["gated_command_runner"]

    def gate(args, **fields):
        gate_calls.append(args[1])
        return original_gate(args, **fields)

    kwargs["apply"] = applied
    kwargs["gated_command_runner"] = gate
    with pytest.raises(job_service.ProviderKeyedInitialApplyJobError):
        job_service.run_fresh_digitalocean_initial_apply_job("apply-job", **kwargs)
    assert gate_calls == ["show"]
    assert not any(event.message == "provider selector absent before initial apply"
                   for event in jobs.current.events)
