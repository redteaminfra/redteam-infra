# Copyright (c) 2026, Oracle and/or its affiliates.
"""A successful keyed core job commits the exact post-apply OCI state digest."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.domain import JobEvent
from app.services.guarded_test_deployment import _execute_guarded_pilot_standard_rti_run
from app.storage.deployment_plan_repository import (
    DeploymentPlanConflictError, SqlAlchemyDeploymentPlanRepository,
    _keyed_core_state_seal_event_data, _read_keyed_core_state_seal,
)
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel

from test_keyed_core_reservation import TARGET, _queued, _reserve, _setup
from test_provider_keyed_oci_core_state import _state


def _prepared(client, tmp_path):
    engagement_id, plan_id = "eng-keyed-seal", "dpl-keyed-seal"
    plans = _setup(engagement_id, plan_id)
    state_path = tmp_path / "terraform.tfstate"
    state = _state()
    for resource in state["resources"]:
        for instance in resource["instances"]:
            attributes = instance["attributes"]
            if resource["mode"] == "managed":
                attributes["freeform_tags"]["barragan_engagement"] = "Disposable"
                if "compartment_id" in attributes:
                    attributes["compartment_id"] = TARGET.compartment_id
    state_path.write_bytes(json.dumps(state).encode())
    evidence = {**plans.get(plan_id).evidence, "terraformStatePath": str(state_path),
                "proxyCount": 2, "elkEnabled": True}
    plans.save(replace(plans.get(plan_id), evidence=evidence))
    queued = _queued("job-keyed-seal", engagement_id, plan_id)
    queued = replace(queued, input={**queued.input, "engagementName": "Disposable",
                                    "proxyCount": 2, "elkEnabled": True,
                                    "corePlanEvidenceSha256": hashlib.sha256(json.dumps(
                                        evidence, sort_keys=True, separators=(",", ":")
                                    ).encode()).hexdigest()})
    _reserve(plans, queued)
    jobs = SqlAlchemyJobRepository()
    running = jobs.save(replace(
        jobs.get(queued.id), status="running", started_at=datetime.now(timezone.utc).isoformat(),
        events=[*queued.events, JobEvent(2, "info", "pilot Standard RTI run started", {})],
    ))
    seal = _read_keyed_core_state_seal(evidence, running.input)
    success = replace(
        running, status="succeeded", finished_at=datetime.now(timezone.utc).isoformat(),
        input={**running.input, "inspectorReadiness": {"ready": True},
               "postCoreSketchContinuationEligible": False,
               "providerKeyedDispatchAuthorized": False},
        events=[*running.events,
                JobEvent(3, "info", "applied OCI core state sealed",
                         _keyed_core_state_seal_event_data(seal)),
                JobEvent(4, "info", "pilot Standard RTI run finished", {
                    "ok": True, "mutationStatus": "deployed", "ansibleStatus": "validated",
                    "finalCleanupStatus": "pending_operator_teardown",
                })],
    )
    return plans, jobs, running, success, state_path, seal


def _assert_unchanged(plans, jobs, running):
    assert jobs.get(running.id) == running
    assert plans.get(running.input["corePlanId"]).status == "applying"
    lease = CoreMutationLeaseModel.query.get(running.input["engagementId"])
    assert lease is not None and lease.operation == "apply"


def test_exact_state_seal_commits_with_core_success(client, tmp_path):
    plans, jobs, running, success, _, seal = _prepared(client, tmp_path)
    assert seal["rawStateSha256"] == hashlib.sha256((tmp_path / "terraform.tfstate").read_bytes()).hexdigest()
    assert set(success.events[-2].data) == {
        "schema", "corePlanEvidenceSha256", "rawStateSha256", "inventorySha256",
        "lineage", "serial", "resourceCount",
    }
    assert "ocid1." not in json.dumps(success.events[-2].data)
    plans.finish_keyed_core_success(success)
    assert jobs.get(running.id).status == "succeeded"
    assert plans.get(running.input["corePlanId"]).status == "applied"
    assert CoreMutationLeaseModel.query.get(running.input["engagementId"]).operation == "provider_keyed_initial"


@pytest.mark.parametrize("tamper", [
    "missing_event", "altered_event", "duplicate_prior_event", "altered_state",
    "missing_state", "malformed_inventory", "symlink_state",
])
def test_state_or_receipt_tampering_rolls_back_atomic_core_success(client, tmp_path, tamper):
    plans, jobs, running, success, state_path, _ = _prepared(client, tmp_path)
    if tamper == "missing_event":
        success = replace(success, events=[*success.events[:2], replace(success.events[-1], sequence=3)])
    elif tamper == "altered_event":
        bad_event = replace(success.events[-2], data={**success.events[-2].data, "serial": 999})
        success = replace(success, events=[*success.events[:-2], bad_event, success.events[-1]])
    elif tamper == "duplicate_prior_event":
        duplicate = replace(success.events[-2], sequence=3)
        success = replace(success, events=[*success.events[:2], duplicate,
                                           replace(success.events[-2], sequence=4),
                                           replace(success.events[-1], sequence=5)])
    elif tamper == "altered_state":
        state_path.write_bytes(state_path.read_bytes() + b" ")
    elif tamper == "missing_state":
        state_path.unlink()
    elif tamper == "symlink_state":
        original = tmp_path / "original.tfstate"
        state_path.rename(original)
        state_path.symlink_to(original)
    else:
        state = json.loads(state_path.read_bytes())
        state["resources"].pop(0)
        state_path.write_bytes(json.dumps(state).encode())
    with pytest.raises(DeploymentPlanConflictError):
        plans.finish_keyed_core_success(success)
    _assert_unchanged(plans, jobs, running)


def test_actual_worker_malformed_state_marks_attention_and_retains_apply_lease(client, tmp_path):
    plans, jobs, running, _, state_path, _ = _prepared(client, tmp_path)
    state_path.write_bytes(b'{"version":4,"resources":[]}')
    result = {
        "ok": True, "deploymentMode": "hold_for_review", "mutationStatus": "deployed",
        "ansibleStatus": "validated", "finalCleanupStatus": "pending_operator_teardown",
    }
    with patch("app.services.guarded_test_deployment.ensure_continuous_inspector_ready",
               return_value={"ready": True}):
        _execute_guarded_pilot_standard_rti_run(
            running.id, {"engagementId": running.input["engagementId"],
                         "corePlanId": running.input["corePlanId"],
                         "target": TARGET.to_dict(), "proxyCount": 2},
            Path(running.input["workspaceDir"]), executor=lambda *args, **kwargs: result,
            repository=jobs,
        )
    failed = jobs.get(running.id)
    assert failed.status == "failed"
    assert failed.events[-1].message.startswith("keyed core post-apply state could not be verified")
    assert all(event.message != "pilot Standard RTI run finished" for event in failed.events)
    assert plans.get(running.input["corePlanId"]).status == "reconciliation_required"
    lease = CoreMutationLeaseModel.query.get(running.input["engagementId"])
    assert lease is not None and lease.operation == "apply"
