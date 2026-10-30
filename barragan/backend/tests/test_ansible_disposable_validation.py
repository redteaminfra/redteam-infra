# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from app.cli.ansible_disposable_validate import main as ansible_cli_main
from app.integrations.ansible_disposable_validation import (
    SSH_PRIVATE_KEY_ENV,
    SSH_PUBLIC_KEY_ENV,
    SSH_SOURCE_CIDR_ENV,
    VALIDATION_INSTANCE_NAME,
    build_ansible_validation_commands,
    build_ansible_validation_workspace,
    execute_disposable_ansible_validation,
    render_ansible_validation_workspace,
    resolve_ansible,
    resolve_ansible_playbook,
)
from app.integrations.oci_disposable_terraform import EXECUTION_CONFIRMATION
from app.integrations.oci_read_validation import (
    BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
    BARRAGAN_TESTING_COMPARTMENT_ID,
    DEFAULT_REGION,
    OciDevelopmentTarget,
    OciSafetyError,
)


class AnsibleDisposableValidationTests(unittest.TestCase):
    def test_builds_preview_for_one_disposable_compute_target(self):
        workspace = build_ansible_validation_workspace()
        body = workspace.to_dict(include_content=True)

        self.assertTrue(body["ok"])
        self.assertFalse(body["mutation"])
        self.assertEqual(body["target"]["name"], "barragan-testing")
        self.assertEqual(body["target"]["compartmentId"], BARRAGAN_TESTING_COMPARTMENT_ID)
        self.assertEqual(body["target"]["region"], DEFAULT_REGION)
        self.assertEqual(
            [resource["type"] for resource in body["resources"]],
            [
                "oci_core_vcn",
                "oci_core_subnet",
                "oci_core_internet_gateway",
                "oci_core_route_table",
                "oci_core_security_list",
                "oci_core_instance",
            ],
        )
        self.assertEqual(body["resources"][-1]["displayName"], VALIDATION_INSTANCE_NAME)
        self.assertIn("compute", body["cleanup"]["verificationCommands"][0])
        rendered = {artifact["path"]: artifact["content"] for artifact in body["artifacts"]}
        self.assertIn("validation_target", rendered["ansible/inventory.ini"])
        self.assertIn("ansible.builtin.ping", rendered["ansible/validate.yml"])
        self.assertIn("gather_facts: true", rendered["ansible/validate.yml"])
        self.assertIn("var.ssh_source_cidr", rendered["main.tf"])
        self.assertIn('values = ["^Canonical-Ubuntu-${var.ubuntu_version}-([.0-9-]+)$"]', rendered["main.tf"])
        self.assertIn('shape               = var.shape', rendered["main.tf"])
        self.assertIn("shape_config", rendered["main.tf"])
        self.assertIn("ocpus         = 1", rendered["main.tf"])
        self.assertIn("memory_in_gbs = 8", rendered["main.tf"])
        self.assertIn("instance_options", rendered["main.tf"])
        self.assertIn("are_legacy_imds_endpoints_disabled = true", rendered["main.tf"])
        self.assertNotIn(r"[\.", rendered["main.tf"])
        self.assertNotIn('source   = "0.0.0.0/0"', rendered["main.tf"])
        self.assertNotIn(BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID, json.dumps(body))

    def test_rejects_non_barragan_testing_targets(self):
        with self.assertRaises(OciSafetyError):
            build_ansible_validation_workspace(
                OciDevelopmentTarget(
                    name="RedTeam",
                    compartment_id=BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
                )
            )

        with self.assertRaises(OciSafetyError):
            build_ansible_validation_workspace(
                OciDevelopmentTarget(
                    name="other",
                    compartment_id="ocid1.compartment.oc1..other",
                )
            )

    def test_renders_workspace_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = render_ansible_validation_workspace(Path(temp_dir))
            rendered = {
                artifact.path: (Path(temp_dir) / artifact.path).read_text(encoding="utf-8")
                for artifact in workspace.artifacts
            }

        self.assertEqual(
            set(rendered),
            {
                "versions.tf",
                "variables.tf",
                "main.tf",
                "terraform.tfvars.json",
                "ansible/inventory.ini",
                "ansible/validate.yml",
                "MANIFEST.md",
            },
        )
        self.assertIn("oci_core_instance", rendered["main.tf"])
        self.assertIn('var.ssh_source_cidr != "0.0.0.0/0"', rendered["variables.tf"])
        self.assertIn(BARRAGAN_TESTING_COMPARTMENT_ID, rendered["terraform.tfvars.json"])
        self.assertIn("ansible.builtin.ping", rendered["ansible/validate.yml"])

    def test_ansible_command_resolution_honors_environment_overrides(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ansible = _executable(temp_dir, "custom-ansible")
            ansible_playbook = _executable(temp_dir, "custom-ansible-playbook")

            ansible_resolution = resolve_ansible(
                env={"ANSIBLE_BIN": ansible, "PATH": ""}
            )
            playbook_resolution = resolve_ansible_playbook(
                env={"ANSIBLE_PLAYBOOK_PATH": ansible_playbook, "PATH": ""}
            )

        self.assertTrue(ansible_resolution.ok)
        self.assertEqual(ansible_resolution.command, ansible)
        self.assertEqual(ansible_resolution.source, "env:ANSIBLE_BIN")
        self.assertTrue(playbook_resolution.ok)
        self.assertEqual(playbook_resolution.command, ansible_playbook)
        self.assertEqual(playbook_resolution.source, "env:ANSIBLE_PLAYBOOK_PATH")

    def test_command_plan_contains_harmless_ansible_validation(self):
        workspace = build_ansible_validation_workspace()
        commands = build_ansible_validation_commands(
            workspace,
            terraform_executable="/tmp/terraform",
            ansible_executable="/tmp/ansible",
            ansible_playbook_executable="/tmp/ansible-playbook",
            ssh_private_key_path="/tmp/key",
            ssh_public_key_path="/tmp/key.pub",
            ssh_source_cidr="198.51.100.10/32",
            host="203.0.113.10",
        )

        self.assertEqual(commands[0][:2], ["/tmp/terraform", "init"])
        self.assertEqual(commands[1][1], "apply")
        self.assertEqual(commands[3][0], "/tmp/ansible")
        self.assertIn("ansible.builtin.wait_for_connection", commands[3])
        self.assertTrue(
            any(part.startswith("--ssh-common-args=") for part in commands[3])
        )
        self.assertNotIn("--ssh-common-args", commands[3])
        self.assertTrue(any("UserKnownHostsFile=ssh/known_hosts" in part for part in commands[3]))
        self.assertEqual(commands[4][-2:], ["-m", "ping"])
        self.assertTrue(any("UserKnownHostsFile=ssh/known_hosts" in part for part in commands[4]))
        self.assertEqual(commands[5][0], "/tmp/ansible-playbook")
        self.assertIn("ansible/validate.yml", commands[5])
        self.assertTrue(any("UserKnownHostsFile=ssh/known_hosts" in part for part in commands[5]))
        self.assertEqual(commands[6][1], "destroy")
        self.assertIn("ssh_source_cidr=198.51.100.10/32", commands[1])
        self.assertEqual(commands[7][5:8], ["compute", "instance", "list"])
        self.assertGreaterEqual(len(commands), 12)

    def test_execute_runs_preflight_compute_ansible_destroy_and_cleanup_with_fake_runner(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            name = Path(command[0]).name
            if name == "terraform" and command[1] == "output":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"public_ip": {"value": "203.0.113.10"}, "vcn_id": {"value": "ocid1.vcn.oc1..validation"}}',
                    stderr="",
                )
            if name == "terraform":
                return subprocess.CompletedProcess(command, 0, stdout=f"{command[1]} ok", stderr="")
            if name in {"ansible", "ansible-playbook"}:
                return subprocess.CompletedProcess(command, 0, stdout="ansible ok", stderr="")
            if "--display-name" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            env = _resolution_env(temp_dir)
            result = execute_disposable_ansible_validation(
                Path(temp_dir),
                runner=runner,
                env=env,
            )

        body = result.to_dict()
        self.assertTrue(body["ok"])
        self.assertEqual(body["mutationStatus"], "destroyed")
        self.assertEqual(body["ansibleStatus"], "validated")
        self.assertEqual(body["finalCleanupStatus"], "verified_clean")
        self.assertTrue(
            any("203.0.113.10" in part for part in body["commandsRun"][3]["command"])
        )
        self.assertEqual(
            [Path(command[0]).name for command in calls if Path(command[0]).name in {"ansible", "ansible-playbook"}],
            ["ansible", "ansible", "ansible-playbook"],
        )
        wait_call = next(command for command in calls if "ansible.builtin.wait_for_connection" in command)
        self.assertTrue(any("UserKnownHostsFile=" in part for part in wait_call))
        self.assertTrue(body["cleanupVerification"]["ok"])
        self.assertEqual(body["cleanupVerification"]["remainingCount"], 0)
        self.assertEqual(
            [check["resource"] for check in body["cleanupVerification"]["checks"]],
            [
                "compute_instance",
                "subnet",
                "internet_gateway",
                "route_table",
                "security_list",
                "vcn",
            ],
        )

    def test_execute_reports_unresolved_ansible_before_mutation(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            if Path(command[0]).name == "terraform":
                self.fail("terraform must not run when Ansible is unresolved")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            env = {
                "OCI_CLI_PATH": _executable(temp_dir, "oci"),
                "TERRAFORM_BIN": _executable(temp_dir, "terraform"),
                SSH_PUBLIC_KEY_ENV: "/tmp/key.pub",
                SSH_PRIVATE_KEY_ENV: "/tmp/key",
                SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
                "PATH": "",
            }
            result = execute_disposable_ansible_validation(
                Path(temp_dir),
                runner=runner,
                env=env,
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertFalse(body["mutation"])
        self.assertEqual(body["mutationStatus"], "ansible_binary_unresolved")
        self.assertIn("ANSIBLE_BIN or ANSIBLE_PATH", body["commandsRun"][0]["stderr"])
        self.assertEqual(len(calls), 2)

    def test_execute_attempts_destroy_and_cleanup_after_ansible_failure(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            name = Path(command[0]).name
            if name == "terraform" and command[1] == "output":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"public_ip": {"value": "203.0.113.10"}, "vcn_id": {"value": "ocid1.vcn.oc1..validation"}}',
                    stderr="",
                )
            if name == "ansible":
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="ssh failed")
            if name == "terraform":
                return subprocess.CompletedProcess(command, 0, stdout=f"{command[1]} ok", stderr="")
            if "--display-name" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = execute_disposable_ansible_validation(
                Path(temp_dir),
                runner=runner,
                env=_resolution_env(temp_dir),
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertTrue(body["mutation"])
        self.assertEqual(body["mutationStatus"], "ansible_failed")
        self.assertEqual(body["ansibleStatus"], "failed")
        self.assertEqual(body["finalCleanupStatus"], "verified_clean")
        self.assertIn("destroy", [command[1] for command in calls if Path(command[0]).name == "terraform"])

    def test_cleanup_counts_terminating_compute_as_remaining(self):
        def runner(command, cwd):
            name = Path(command[0]).name
            if name == "terraform" and command[1] == "output":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"public_ip": {"value": "203.0.113.10"}}',
                    stderr="",
                )
            if name in {"terraform", "ansible", "ansible-playbook"}:
                return subprocess.CompletedProcess(command, 0, stdout=f"{command[1]} ok", stderr="")
            if "compute" in command and "instance" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout='{"data": [{"display-name": "barragan-disposable-ansible-validation", "lifecycle-state": "TERMINATING"}]}',
                    stderr="",
                )
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = execute_disposable_ansible_validation(
                Path(temp_dir),
                runner=runner,
                env=_resolution_env(temp_dir),
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertEqual(body["mutationStatus"], "destroyed")
        self.assertEqual(body["finalCleanupStatus"], "cleanup_not_verified")
        self.assertFalse(body["cleanupVerification"]["ok"])
        self.assertEqual(body["cleanupVerification"]["remainingCount"], 1)
        self.assertIn("compute_instance", body["cleanupVerification"]["error"])

    def test_execute_reports_missing_ssh_source_cidr_before_mutation(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            if Path(command[0]).name == "terraform":
                self.fail("terraform must not run when SSH source CIDR is unresolved")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            env = _resolution_env(temp_dir)
            env.pop(SSH_SOURCE_CIDR_ENV)
            result = execute_disposable_ansible_validation(
                Path(temp_dir),
                runner=runner,
                env=env,
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertFalse(body["mutation"])
        self.assertEqual(body["mutationStatus"], "ssh_key_unresolved")
        self.assertIn(SSH_SOURCE_CIDR_ENV, body["commandsRun"][0]["stderr"])

    def test_cli_previews_renders_and_prints_commands_without_cloud_mutation(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = ansible_cli_main(["--pretty"])

        self.assertEqual(exit_code, 0)
        preview = json.loads(stdout.getvalue())
        self.assertFalse(preview["mutation"])
        self.assertEqual(preview["mode"], "ansible_validation_render_preview")
        self.assertIsNone(preview["renderResult"])
        self.assertEqual(preview["resources"][-1]["type"], "oci_core_instance")

        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = ansible_cli_main(["--render-dir", temp_dir, "--pretty"])

            self.assertEqual(exit_code, 0)
            rendered = json.loads(stdout.getvalue())
            self.assertFalse(rendered["renderResult"]["mutation"])
            self.assertTrue((Path(temp_dir) / "main.tf").exists())
            self.assertTrue((Path(temp_dir) / "ansible" / "validate.yml").exists())

        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = ansible_cli_main(
                [
                    "--print-commands",
                    "--ssh-private-key-path",
                    "/tmp/operator-key",
                    "--ssh-public-key-path",
                    "/tmp/operator-key.pub",
                    "--ssh-source-cidr",
                    "198.51.100.10/32",
                    "--pretty",
                ]
            )

        self.assertEqual(exit_code, 0)
        printed = json.loads(stdout.getvalue())
        self.assertTrue(printed["ok"])
        self.assertFalse(printed["mutation"])
        self.assertEqual(printed["mode"], "ansible_validation_print_commands")
        self.assertFalse(printed["sshConfiguration"]["privateKeyMaterialRead"])
        self.assertNotIn("content", printed["artifacts"][0])
        planned = printed["commands"]["planned"]
        self.assertEqual(planned[0][1], "init")
        self.assertEqual(planned[1][1], "apply")
        self.assertIn("198.51.100.10/32", "\n".join(" ".join(command) for command in planned))
        self.assertTrue(
            any("ansible.builtin.wait_for_connection" in command for command in planned)
        )
        self.assertEqual(planned[6][1], "destroy")
        self.assertEqual(printed["commands"]["cleanupVerification"], planned[7:])

    def test_cli_refuses_execution_without_confirmation_flags(self):
        stderr = StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stderr(stderr):
            ansible_cli_main(["--execute"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--execute requires --render-dir", stderr.getvalue())

        with tempfile.TemporaryDirectory() as temp_dir:
            stderr = StringIO()
            with self.assertRaises(SystemExit) as raised, redirect_stderr(stderr):
                ansible_cli_main(["--execute", "--render-dir", temp_dir])

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("--confirm-mutation", stderr.getvalue())

            stderr = StringIO()
            with self.assertRaises(SystemExit) as raised, redirect_stderr(stderr):
                ansible_cli_main(
                    [
                        "--execute",
                        "--render-dir",
                        temp_dir,
                        "--confirm-mutation",
                        EXECUTION_CONFIRMATION,
                    ]
                )

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("--confirm-destroy-cleanup", stderr.getvalue())

    def test_cli_execute_passes_operator_arguments_to_guarded_integration(self):
        class FakeResult:
            def to_dict(self):
                return {
                    "ok": True,
                    "mode": "ansible_guarded_execute",
                    "mutation": False,
                }

        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with patch(
                "app.cli.ansible_disposable_validate.execute_disposable_ansible_validation",
                return_value=FakeResult(),
            ) as execute, redirect_stdout(stdout):
                exit_code = ansible_cli_main(
                    [
                        "--execute",
                        "--render-dir",
                        temp_dir,
                        "--confirm-mutation",
                        EXECUTION_CONFIRMATION,
                        "--confirm-destroy-cleanup",
                        "--ssh-private-key-path",
                        "/tmp/operator-key",
                        "--ssh-public-key-path",
                        "/tmp/operator-key.pub",
                        "--ssh-source-cidr",
                        "198.51.100.10/32",
                    ]
                )

        self.assertEqual(exit_code, 0)
        execute.assert_called_once_with(
            Path(temp_dir),
            ssh_private_key_path="/tmp/operator-key",
            ssh_public_key_path="/tmp/operator-key.pub",
            ssh_source_cidr="198.51.100.10/32",
        )


def _executable(directory: str, name: str) -> str:
    path = Path(directory) / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _resolution_env(directory: str) -> dict[str, str]:
    bin_dir = Path(directory) / "bin"
    bin_dir.mkdir()
    return {
        "OCI_CLI_PATH": _executable(str(bin_dir), "oci"),
        "TERRAFORM_BIN": _executable(str(bin_dir), "terraform"),
        "ANSIBLE_BIN": _executable(str(bin_dir), "ansible"),
        "ANSIBLE_PLAYBOOK_BIN": _executable(str(bin_dir), "ansible-playbook"),
        SSH_PUBLIC_KEY_ENV: "/tmp/barragan-validation.pub",
        SSH_PRIVATE_KEY_ENV: "/tmp/barragan-validation",
        SSH_SOURCE_CIDR_ENV: "198.51.100.10/32",
        "PATH": "",
    }


if __name__ == "__main__":
    unittest.main()
