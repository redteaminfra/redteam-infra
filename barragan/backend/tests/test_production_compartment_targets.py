# Copyright (c) 2026, Oracle and/or its affiliates.
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.integrations import oci_deployment_targets as targets
from app.integrations.pilot_standard_rti import build_pilot_standard_rti_workspace
from app.services.guarded_test_deployment import (
    pilot_standard_rti_readiness,
    run_guarded_pilot_standard_rti,
)


@pytest.fixture(autouse=True)
def configured_production_targets(tmp_path, monkeypatch):
    config_path = tmp_path / "oci-deployment-targets.json"
    config_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "expectedProductionTargetCount": 4,
                "productionTargets": [
                    {
                        "name": f"production-{letter}",
                        "compartmentId": f"ocid1.compartment.oc1..approvedtarget{letter}",
                        "region": "us-sanjose-1",
                    }
                    for letter in "abcd"
                ],
            }
        ),
        encoding="utf-8",
    )
    configured = targets._load_production_targets(config_path)
    monkeypatch.setattr(targets, "PRODUCTION_OCI_TARGETS", configured)
    monkeypatch.setattr(
        targets,
        "OCI_DEPLOYMENT_TARGETS",
        (targets.BARRAGAN_TESTING_TARGET, *configured),
    )


def _production_engagement():
    target = targets.PRODUCTION_OCI_TARGETS[0]
    return SimpleNamespace(
        id="eng-prod01",
        name="PROD01",
        template_id="dev-infra",
        input_parameters={
            "proxyCount": 1,
            "deploymentTarget": {
                "provider": "oci",
                "name": target.name,
                "compartmentId": target.compartment_id,
                "region": target.region,
            },
        },
    )


def test_production_readiness_selects_persisted_target_and_lists_testing_plus_production():
    engagement = _production_engagement()
    with (
        patch("app.services.guarded_test_deployment.get_engagement", return_value=engagement),
        patch("app.services.guarded_test_deployment.runtime_value", return_value="production"),
    ):
        readiness = pilot_standard_rti_readiness(engagement_id=engagement.id, env={"PATH": ""})

    assert readiness["target"]["name"] == "production-a"
    assert [target["name"] for target in readiness["availableTargets"]] == [
        "barragan-testing",
        "production-a",
        "production-b",
        "production-c",
        "production-d",
    ]
    assert readiness["confirmationToken"] == "deploy-prod01-to-production-a"


def test_selected_target_is_pinned_in_rendered_terraform_validation():
    target = targets.PRODUCTION_OCI_TARGETS[3]
    workspace = build_pilot_standard_rti_workspace(target, engagement_name="PROD04", proxy_count=1)
    variables = next(artifact.content for artifact in workspace.artifacts if artifact.path == "variables.tf")
    tfvars = next(artifact.content for artifact in workspace.artifacts if artifact.path == "terraform.tfvars.json")

    assert target.compartment_id in variables
    assert target.compartment_id in tfvars
    assert "pinned production-d compartment" in variables
    assert targets.BARRAGAN_TESTING_TARGET.compartment_id not in variables


def test_executor_receives_persisted_production_target_not_request_target(tmp_path):
    engagement = _production_engagement()
    received = {}

    def executor(_workspace_dir: Path, **kwargs):
        received.update(kwargs)
        return {"ok": True, "mutationStatus": "deployed"}

    durable_run = SimpleNamespace(
        run_directory=tmp_path / "run",
        state_path=tmp_path / "state.tfstate",
        terraform_data_dir=tmp_path / "tfdata",
        state_locator="engagement/eng-prod01/core/terraform.tfstate",
    )
    with (
        patch("app.services.guarded_test_deployment.get_engagement", return_value=engagement),
        patch("app.services.guarded_test_deployment.runtime_value", return_value="production"),
        patch("app.services.guarded_test_deployment.prepare_core_deployment_run", return_value=durable_run),
        patch("app.services.engagement_teardown.assert_engagement_mutation_allowed"),
    ):
        run_guarded_pilot_standard_rti(
            {
                "engagementId": engagement.id,
                "confirmMutation": "deploy-prod01-to-production-a",
                "sshSourceCidrs": ["192.0.2.10/32"],
                "deploymentTarget": targets.BARRAGAN_TESTING_TARGET.to_dict(),
            },
            executor=executor,
        )

    assert received["target"] == targets.PRODUCTION_OCI_TARGETS[0]


def test_production_readiness_keeps_barragan_testing_as_a_valid_target():
    engagement = SimpleNamespace(
        id="eng-test",
        name="TEST",
        template_id="dev-infra",
        input_parameters={"proxyCount": 1},
    )
    with (
        patch("app.services.guarded_test_deployment.get_engagement", return_value=engagement),
        patch("app.services.guarded_test_deployment.runtime_value", return_value="production"),
    ):
        readiness = pilot_standard_rti_readiness(engagement_id=engagement.id, env={"PATH": ""})

    assert readiness["target"]["name"] == "barragan-testing"
    assert readiness["confirmationToken"] == "mutate-barragan-testing"
