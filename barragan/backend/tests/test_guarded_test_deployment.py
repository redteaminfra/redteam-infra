# Copyright (c) 2026, Oracle and/or its affiliates.
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.integrations.ansible_disposable_validation import (
    SSH_PRIVATE_KEY_ENV,
    SSH_PUBLIC_KEY_ENV,
    SSH_SOURCE_CIDR_ENV,
    VALIDATION_INSTANCE_NAME,
)
from app.integrations.oci_disposable_terraform import EXECUTION_CONFIRMATION
from app.integrations.oci_read_validation import BARRAGAN_TESTING_COMPARTMENT_ID, DEFAULT_REGION
from app.services.guarded_test_deployment import (
    GuardedDeploymentConfirmationError,
    disposable_deployment_readiness,
    run_guarded_disposable_deployment,
)


class GuardedTestDeploymentServiceTests(unittest.TestCase):
    def test_readiness_exposes_target_guardrails_and_command_resolution(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            oci_path = _executable(temp_dir, "oci")
            terraform_path = _executable(temp_dir, "terraform")
            ansible_path = _executable(temp_dir, "ansible")
            ansible_playbook_path = _executable(temp_dir, "ansible-playbook")
            readiness = disposable_deployment_readiness(
                env={
                    "OCI_CLI_PATH": oci_path,
                    "TERRAFORM_BIN": terraform_path,
                    "ANSIBLE_BIN": ansible_path,
                    "ANSIBLE_PLAYBOOK_BIN": ansible_playbook_path,
                    SSH_PUBLIC_KEY_ENV: "/tmp/barragan-validation.pub",
                    SSH_PRIVATE_KEY_ENV: "/tmp/barragan-validation",
                    SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                    "PATH": "",
                }
            )

        self.assertEqual(readiness["target"]["name"], "barragan-testing")
        self.assertEqual(readiness["target"]["compartmentId"], BARRAGAN_TESTING_COMPARTMENT_ID)
        self.assertEqual(readiness["target"]["region"], DEFAULT_REGION)
        self.assertEqual(readiness["target"]["auth"], "instance_principal")
        self.assertEqual(
            readiness["mutationScope"],
            "disposable compute plus harmless Ansible validation only",
        )
        self.assertEqual(readiness["expectedInstanceDisplayName"], VALIDATION_INSTANCE_NAME)
        self.assertEqual(readiness["confirmationToken"], EXECUTION_CONFIRMATION)
        self.assertTrue(readiness["cleanupAcknowledgement"]["required"])
        self.assertTrue(readiness["commandResolution"]["oci"]["ok"])
        self.assertTrue(readiness["commandResolution"]["terraform"]["ok"])
        self.assertTrue(readiness["commandResolution"]["ansible"]["ok"])
        self.assertTrue(readiness["commandResolution"]["ansiblePlaybook"]["ok"])
        self.assertTrue(readiness["sshKeyConfiguration"]["publicKeyConfigured"])
        self.assertTrue(readiness["sshKeyConfiguration"]["privateKeyConfigured"])
        self.assertTrue(readiness["sshKeyConfiguration"]["sourceCidrConfigured"])
        self.assertEqual(readiness["sshIngress"]["sourceCidrEnv"], SSH_SOURCE_CIDR_ENV)
        self.assertFalse(readiness["sshIngress"]["allowsPublicInternet"])
        self.assertTrue(readiness["sshReadiness"]["bounded"])
        self.assertEqual(readiness["sshReadiness"]["module"], "ansible.builtin.wait_for_connection")
        self.assertEqual(readiness["sshReadiness"]["knownHostsPath"], "ssh/known_hosts")
        self.assertIn("disposable workspace", readiness["sshReadiness"]["hostKeyPolicy"])
        self.assertEqual(readiness["commands"]["planned"][1][1], "apply")
        self.assertIn("ssh_source_cidr=198.51.100.10/32", readiness["commands"]["planned"][1])
        self.assertIn("ansible.builtin.wait_for_connection", readiness["commands"]["planned"][3])
        self.assertEqual(readiness["commands"]["planned"][4][-2:], ["-m", "ping"])
        self.assertEqual(readiness["commands"]["planned"][7][0], oci_path)
        self.assertEqual(readiness["commands"]["cleanupVerification"][0][0], oci_path)
        self.assertIn("RedTeam", readiness["guardrails"]["noTouchCompartments"])
        self.assertIn("ansible.builtin.ping", readiness["guardrails"]["harmlessAnsibleActions"])
        self.assertIn("Vault/KMS/secrets", readiness["guardrails"]["disallowedResourceFamilies"])

    def test_run_rejects_missing_confirmation_without_execution(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with self.assertRaises(GuardedDeploymentConfirmationError):
            run_guarded_disposable_deployment({}, executor=executor)

        self.assertEqual(calls, [])

    def test_run_rejects_missing_cleanup_ack_without_execution(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with self.assertRaises(GuardedDeploymentConfirmationError):
            run_guarded_disposable_deployment(
                {"confirmMutation": EXECUTION_CONFIRMATION},
                executor=executor,
            )

        self.assertEqual(calls, [])

    def test_run_rejects_public_ssh_source_cidr_without_execution(self):
        calls = []

        def executor(workspace_dir, **kwargs):
            calls.append(workspace_dir)
            return {"ok": True}

        with self.assertRaises(GuardedDeploymentConfirmationError):
            run_guarded_disposable_deployment(
                {
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": True,
                    "sshSourceCidr": "0.0.0.0/0",
                },
                executor=executor,
            )

        self.assertEqual(calls, [])

    def test_run_invokes_executor_with_confirmed_workspace_dir(self):
        calls = []

        class FakeResult:
            def to_dict(self):
                return {
                    "ok": True,
                    "mutationStatus": "destroyed",
                    "finalCleanupStatus": "verified_clean",
                }

        def executor(workspace_dir, **kwargs):
            calls.append((workspace_dir, kwargs))
            return FakeResult()

        result = run_guarded_disposable_deployment(
            {
                "confirmMutation": EXECUTION_CONFIRMATION,
                "confirmDestroyCleanup": True,
                "workspaceDir": "/tmp/barragan-test-service",
                "sshPrivateKeyPath": "/tmp/private-key",
                "sshPublicKeyPath": "/tmp/public-key.pub",
                "sshSourceCidr": "198.51.100.10/32",
            },
            executor=executor,
        )

        self.assertEqual(calls[0][0], Path("/tmp/barragan-test-service"))
        self.assertEqual(calls[0][1]["ssh_private_key_path"], "/tmp/private-key")
        self.assertEqual(calls[0][1]["ssh_public_key_path"], "/tmp/public-key.pub")
        self.assertEqual(calls[0][1]["ssh_source_cidr"], "198.51.100.10/32")
        self.assertEqual(result["deployment"]["mutationStatus"], "destroyed")
        self.assertEqual(result["deployment"]["finalCleanupStatus"], "verified_clean")


class GuardedTestDeploymentApiTests(unittest.TestCase):
    def test_readiness_endpoint_returns_operator_payload(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        response = client.get("/api/orchestrator/barragan-testing/disposable/readiness")
        body = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["readiness"]["confirmationToken"], EXECUTION_CONFIRMATION)
        self.assertEqual(body["readiness"]["expectedInstanceDisplayName"], VALIDATION_INSTANCE_NAME)
        self.assertTrue(body["readiness"]["imdsHardening"]["legacyEndpointsDisabled"])
        self.assertEqual(
            body["readiness"]["imdsHardening"]["terraformAttribute"],
            "instance_options.are_legacy_imds_endpoints_disabled",
        )

    def test_run_endpoint_rejects_bad_confirmation_before_execution(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        response = client.post(
            "/api/orchestrator/barragan-testing/disposable/run",
            json={"confirmMutation": "wrong", "confirmDestroyCleanup": True},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("confirmMutation", response.get_json()["error"])

    def test_run_endpoint_returns_fake_execution_result(self):
        from app import create_app
        from app.core.config import TestConfig

        app = create_app(TestConfig)
        client = app.test_client()

        with patch(
            "app.asgi.run_guarded_disposable_deployment",
            return_value={
                "deployment": {
                    "ok": True,
                    "mutationStatus": "destroyed",
                    "finalCleanupStatus": "verified_clean",
                }
            },
        ) as mocked:
            response = client.post(
                "/api/orchestrator/barragan-testing/disposable/run",
                json={
                    "confirmMutation": EXECUTION_CONFIRMATION,
                    "confirmDestroyCleanup": True,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["deployment"]["ok"])
        mocked.assert_called_once()


def _executable(directory: str, name: str) -> str:
    path = Path(directory) / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


if __name__ == "__main__":
    unittest.main()
