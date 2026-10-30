# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted append handoffs never replay an uncertain Terraform child."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services.provider_keyed_append_apply_job import (
    ProviderKeyedAppendApplyJobError,
    _completed_apply_child_receipt,
    reconcile_interrupted_digitalocean_edge_append_apply,
)
from app.storage.job_repository import SqliteJobRepository, StoredJobRun, job_event_digest


NOW = "2026-10-13T00:00:00+00:00"
ENG = "eng-test"
PARENT = "job-provider-keyed-append-case"
CHILD = "job-provider-keyed-append-apply-case"


def _job(id, action, status, input, events):
    return StoredJobRun(id, action, status, f"engagement:{ENG}", "engagement", ENG,
                        "operator", input, [], NOW, NOW, NOW if status == "succeeded" else None,
                        events)


def _case(tmp_path, *, child_status=None):
    jobs = SqliteJobRepository(tmp_path / "jobs.sqlite")
    root = tmp_path / "state" / "digitalocean" / "workspace"
    root.mkdir(parents=True)
    state = root / "terraform.tfstate"
    state.write_text(json.dumps({"resources": []}))
    sha = hashlib.sha256(state.read_bytes()).hexdigest()
    (root / ".barragan-apply-phase.json").write_text(json.dumps({"phase": "applied"}))
    binary = "/usr/bin/terraform"
    plan_path = str(root / ".barragan-edge-append.tfplan")
    def argv_sha(phase):
        argv = [binary, *(["show", "-json", plan_path] if phase == "show" else
                         ["apply", "-input=false", "-lock=true", "-no-color", plan_path])]
        return hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest()
    plan = _job("job-plan", "provider_keyed_edge_append_plan", "succeeded", {}, [
        JobEvent(1, "info", "reviewed append plan saved", {"stateSha256": sha,
            "terraformBinaryPath": binary, "planPath": plan_path})])
    jobs.save(plan)
    parent = _job(PARENT, "provider_keyed_edge_append", "running", {
        "phase": "apply_reserved", "engagementId": ENG,
        "corePlanId": "core-plan", "planJobId": plan.id,
        "planJournalSha256": job_event_digest(plan.events),
        "applyJobId": CHILD, "chainId": "chain-a",
        "applyReservationId": "f" * 32,
    }, [JobEvent(1, "info", "provider append Apply reserved", {
        "planJournalSha256": job_event_digest(plan.events),
        "reservationId": "f" * 32})])
    jobs.save(parent)
    if child_status:
        entries = [
            ("provider append Apply child reserved", {"planJournalSha256":
                job_event_digest(plan.events), "reservationId": "f" * 32}),
            ("provider append Apply preflight started", {}),
            ("provider append key staging intended", {}),
            ("provider append command intent fenced", {"phase": "show",
                "invocationId": "show", "argvSha256": argv_sha("show")}),
            ("provider append command started before GO", {"phase": "show", "invocationId": "show",
                "bootId": "boot", "pid": 1, "pgid": 1, "startTicks": 1}),
            ("provider append command result fenced", {"phase": "show", "invocationId": "show",
                "returnCode": 0}),
            ("provider append retained membership verified", {
                "stateSha256": sha, "providerIds": ["1", "2", "3", "4"]}),
            ("provider append phase apply_started", {"stateSha256": sha}),
            ("provider append command intent fenced", {"phase": "apply",
                "invocationId": "apply", "argvSha256": argv_sha("apply")}),
            ("provider append command started before GO", {"phase": "apply", "invocationId": "apply",
                "bootId": "boot", "pid": 2, "pgid": 2, "startTicks": 2}),
            ("provider append command result fenced", {"phase": "apply", "invocationId": "apply",
                "returnCode": 0}),
            ("provider append expanded membership verified", {
                "stateSha256": sha, "providerIds": ["1", "2", "3", "4", "9"]}),
            ("provider append apply completed", {"stateSha256": sha,
                "newEdgeAddress": "edge-02", "newEdgeProviderId": "9",
                "newEdgePublicIp": "203.0.113.9", "providerMembershipVerified": True}),
        ] if child_status == "succeeded" else [
            ("provider append Apply child reserved", {"planJournalSha256":
                job_event_digest(plan.events), "reservationId": "f" * 32}),
            ("provider append command started before GO", {"pid": 123}),
        ]
        child = _job(CHILD, "provider_keyed_edge_append_apply", child_status,
                     {"parentJobId": PARENT, "mutation": True}, [
            JobEvent(index, "info", message, data)
            for index, (message, data) in enumerate(entries, 1)])
        jobs.save(child)
    chains = SimpleNamespace(list_for_engagement=lambda _eng: [
        SimpleNamespace(chain_id="chain-a", terraform_working_directory=str(root),
                        nodes=[{"providerInstanceId": "1"}, {"providerInstanceId": "2"}]),
        SimpleNamespace(chain_id="chain-b", terraform_working_directory=str(root),
                        nodes=[{"providerInstanceId": "3"}, {"providerInstanceId": "4"}]),
    ])
    kwargs = dict(state_root=tmp_path / "state", job_repository=jobs,
                  sketch_repository=chains,
                  lease_lookup=lambda _eng: ("core-plan", "provider_keyed_edge_append"))
    return jobs, kwargs


def test_absent_child_recovers_review_without_terraform(tmp_path):
    jobs, kwargs = _case(tmp_path)
    repaired = reconcile_interrupted_digitalocean_edge_append_apply(PARENT, **kwargs)
    assert repaired.input["phase"] == "awaiting_apply"
    assert repaired.events[-1].message == "provider append Apply reservation repaired"
    assert jobs.get(CHILD) is None


def test_succeeded_child_hands_off_without_second_apply(tmp_path):
    jobs, kwargs = _case(tmp_path, child_status="succeeded")
    before = jobs.get(CHILD)
    repaired = reconcile_interrupted_digitalocean_edge_append_apply(PARENT, **kwargs)
    assert repaired.input["phase"] == "awaiting_host_proof"
    assert repaired.input["applyJournalSha256"] == job_event_digest(before.events)
    assert jobs.get(CHILD) == before
    with pytest.raises(ProviderKeyedAppendApplyJobError):
        reconcile_interrupted_digitalocean_edge_append_apply(PARENT, **kwargs)


def test_running_child_never_replays_even_after_claim_expiry(tmp_path):
    jobs, kwargs = _case(tmp_path, child_status="running")
    before = jobs.get(CHILD)
    with pytest.raises(ProviderKeyedAppendApplyJobError):
        reconcile_interrupted_digitalocean_edge_append_apply(PARENT, **kwargs)
    assert jobs.get(CHILD) == before
    assert jobs.get(PARENT).input["phase"] == "apply_reserved"


def test_terminal_only_succeeded_child_cannot_promote_parent(tmp_path):
    jobs, kwargs = _case(tmp_path, child_status="succeeded")
    child = jobs.get(CHILD)
    jobs.save(replace(child, events=[child.events[0], child.events[-1]]))
    with pytest.raises(ProviderKeyedAppendApplyJobError):
        reconcile_interrupted_digitalocean_edge_append_apply(PARENT, **kwargs)
    assert jobs.get(PARENT).input["phase"] == "apply_reserved"


def test_failed_then_success_append_journal_cannot_promote(tmp_path):
    jobs, _kwargs = _case(tmp_path, child_status="succeeded")
    parent, child, plan = jobs.get(PARENT), jobs.get(CHILD), jobs.get("job-plan")
    injected = [*child.events[:3], JobEvent(4, "error", "provider append command failed", {}),
                *(replace(event, sequence=event.sequence + 1)
                  for event in child.events[3:])]
    with pytest.raises(ValueError):
        _completed_apply_child_receipt(replace(child, events=injected), parent,
            job_event_digest(plan.events), plan.events[-1].data, {"1", "2", "3", "4"})
