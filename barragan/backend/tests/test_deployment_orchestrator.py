# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.integrations.command_resolution import CommandResolution
from app.integrations.oci_read_validation import OciDevelopmentTarget, OciReadValidationResult, OciSafetyError
from app.services.access_plans import PlatformAccessUser
from app.services.deployment_orchestrator import plan_standard_rti_deployment
from tests.test_catalog_service import valid_standard_rti_payload


class DeploymentOrchestratorTests(unittest.TestCase):
    def test_plan_only_standard_rti_deployment_end_to_end(self):
        access_user = PlatformAccessUser("user-1", "alice", "secret://users/alice", ["view", "operate"])

        with tempfile.TemporaryDirectory() as render_dir:
            result = plan_standard_rti_deployment(
                "eng-orchestrator-test",
                valid_standard_rti_payload(),
                access_users=[access_user],
                render_destination=Path(render_dir),
                render_job_id="job-orchestrator-render",
            ).to_dict()

            self.assertEqual(result["revision"]["status"], "compiled")
            self.assertEqual(result["providerPlan"]["mode"], "dry_run")
            self.assertEqual(result["providerPreflight"]["status"], "not_run")
            self.assertTrue(result["providerPreflight"]["required"])
            self.assertFalse(result["providerPreflight"]["mutation"])
            self.assertFalse(result["deployReadiness"]["ready"])
            self.assertEqual(result["deployReadiness"]["blockedBy"][0]["id"], "oci-read-validation")
            self.assertFalse(result["terraformIntent"]["mutation"])
            self.assertFalse(result["ansibleIntent"]["mutation"])
            self.assertEqual(result["accessPlan"]["targets"][0]["accessKind"], "core_named")
            self.assertIsNotNone(result["renderResult"])
            self.assertEqual(
                [file["path"] for file in result["terraformFiles"]],
                ["versions.tf", "variables.tf", "main.tf"],
            )
            self.assertTrue(all(not file["path"].startswith("/") for file in result["terraformFiles"]))
            self.assertNotIn("terraform.tfstate", str(result["terraformFiles"]))
            self.assertNotIn("terraform.tfvars", str(result["terraformFiles"]))
            self.assertIn('resource "oci_core_instance" "homebase"', result["terraformFiles"][2]["source"])
            self.assertTrue((Path(result["renderResult"]["root"]) / "manifest.yaml").exists())
            self.assertFalse(any(event["data"].get("mutation") for event in result["events"]))

    def test_plan_only_standard_rti_deployment_can_skip_render_write(self):
        result = plan_standard_rti_deployment(
            "eng-orchestrator-test",
            valid_standard_rti_payload(),
        ).to_dict()

        self.assertIsNone(result["renderResult"])
        self.assertEqual(result["events"][-1]["message"], "plan-only deployment completed")

    def test_passed_provider_preflight_marks_deploy_ready(self):
        def runner(command):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"data": [{"id": "resource-1"}]}),
                stderr="",
            )

        result = plan_standard_rti_deployment(
            "eng-orchestrator-test",
            valid_standard_rti_payload(),
            provider_preflight_runner=runner,
        ).to_dict()

        self.assertEqual(result["providerPreflight"]["status"], "passed")
        self.assertTrue(result["providerPreflight"]["ok"])
        self.assertTrue(result["deployReadiness"]["ready"])
        self.assertEqual(result["deployReadiness"]["blockedBy"], [])
        self.assertIn(
            "required provider preflight passed",
            [event["message"] for event in result["events"]],
        )

    def test_failed_provider_preflight_blocks_deploy_readiness(self):
        def runner(command):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="NotAuthorizedOrNotFound")

        result = plan_standard_rti_deployment(
            "eng-orchestrator-test",
            valid_standard_rti_payload(),
            provider_preflight_runner=runner,
        ).to_dict()

        self.assertEqual(result["providerPreflight"]["status"], "failed")
        self.assertFalse(result["providerPreflight"]["ok"])
        self.assertFalse(result["deployReadiness"]["ready"])
        self.assertEqual(result["deployReadiness"]["blockedBy"][0]["status"], "failed")
        failure_events = [
            event for event in result["events"] if event["message"] == "required provider preflight failed"
        ]
        self.assertEqual(failure_events[0]["level"], "error")
        self.assertFalse(failure_events[0]["data"]["deployReady"])

    def test_cached_provider_preflight_result_must_target_barragan_testing(self):
        unsafe_result = OciReadValidationResult(
            target=OciDevelopmentTarget(name="RedTeam-1"),
            checks=[],
            command_resolution=CommandResolution("oci", "/tmp/oci", "test", ("OCI_CLI_PATH",)),
        )

        with self.assertRaises(OciSafetyError):
            plan_standard_rti_deployment(
                "eng-orchestrator-test",
                valid_standard_rti_payload(),
                provider_preflight_result=unsafe_result,
            )


if __name__ == "__main__":
    unittest.main()
