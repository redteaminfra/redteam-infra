# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from app.cli.oci_disposable_validate import main
from app.integrations.oci_disposable_terraform import (
    EXECUTION_CONFIRMATION,
    VALIDATION_VCN_NAME,
    build_disposable_execution_commands,
    build_disposable_terraform_workspace,
    execute_disposable_terraform_validation,
    rendered_artifacts_contain_no_no_touch_compartment_ids,
    render_disposable_terraform_workspace,
    resolve_terraform,
)
from app.integrations.oci_read_validation import (
    BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
    BARRAGAN_TESTING_COMPARTMENT_ID,
    DEFAULT_REGION,
    OciDevelopmentTarget,
    OciSafetyError,
)


def _executable(directory: str, name: str) -> str:
    path = Path(directory) / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _resolution_env(directory: str) -> dict[str, str]:
    return {
        "OCI_CLI_PATH": _executable(directory, "oci"),
        "TERRAFORM_BIN": _executable(directory, "terraform"),
        "PATH": "",
    }


class OciDisposableTerraformTests(unittest.TestCase):
    def test_builds_non_mutating_preview_for_barragan_testing(self):
        workspace = build_disposable_terraform_workspace()
        body = workspace.to_dict(include_content=True)

        self.assertTrue(body["ok"])
        self.assertFalse(body["mutation"])
        self.assertEqual(body["target"]["name"], "barragan-testing")
        self.assertEqual(body["target"]["compartmentId"], BARRAGAN_TESTING_COMPARTMENT_ID)
        self.assertEqual(body["target"]["region"], DEFAULT_REGION)
        self.assertEqual(
            [resource["displayName"] for resource in body["resources"]],
            [VALIDATION_VCN_NAME],
        )
        self.assertIn("verificationCommands", body["cleanup"])
        self.assertIn(VALIDATION_VCN_NAME, body["cleanup"]["verificationCommands"][0])
        self.assertIn("does not run terraform init", body["notice"])
        self.assertNotIn(BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID, json.dumps(body))
        self.assertTrue(rendered_artifacts_contain_no_no_touch_compartment_ids(workspace))

    def test_rejects_non_barragan_testing_targets(self):
        with self.assertRaises(OciSafetyError):
            build_disposable_terraform_workspace(
                OciDevelopmentTarget(
                    name="RedTeam",
                    compartment_id=BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
                )
            )

        with self.assertRaises(OciSafetyError):
            build_disposable_terraform_workspace(
                OciDevelopmentTarget(
                    name="other",
                    compartment_id="ocid1.compartment.oc1..other",
                )
            )

    def test_rejects_non_san_jose_region_for_disposable_workspace(self):
        with self.assertRaises(OciSafetyError):
            build_disposable_terraform_workspace(
                OciDevelopmentTarget(
                    compartment_id=BARRAGAN_TESTING_COMPARTMENT_ID,
                    region="us-ashburn-1",
                )
            )

    def test_renders_workspace_files_without_no_touch_parent_ocid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = render_disposable_terraform_workspace(Path(temp_dir))

            rendered = {
                artifact.path: (Path(temp_dir) / artifact.path).read_text()
                for artifact in workspace.artifacts
            }
            self.assertEqual(
                set(rendered),
                {"versions.tf", "variables.tf", "main.tf", "terraform.tfvars.json", "MANIFEST.md"},
            )
            self.assertIn("oci_core_vcn", rendered["main.tf"])
            self.assertIn(f'var.region == "{DEFAULT_REGION}"', rendered["variables.tf"])
            self.assertIn(BARRAGAN_TESTING_COMPARTMENT_ID, rendered["terraform.tfvars.json"])
            self.assertNotIn(BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID, "\n".join(rendered.values()))

    def test_cli_previews_and_renders_without_cloud_mutation(self):
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["--pretty"])

        self.assertEqual(exit_code, 0)
        preview = json.loads(stdout.getvalue())
        self.assertFalse(preview["mutation"])
        self.assertIsNone(preview["renderResult"])
        self.assertEqual(preview["resources"][0]["type"], "oci_core_vcn")

        with tempfile.TemporaryDirectory() as temp_dir:
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["--render-dir", temp_dir, "--pretty"])

            self.assertEqual(exit_code, 0)
            rendered = json.loads(stdout.getvalue())
            self.assertFalse(rendered["renderResult"]["mutation"])
            self.assertTrue((Path(temp_dir) / "main.tf").exists())
            self.assertTrue((Path(temp_dir) / "MANIFEST.md").exists())

    def test_cli_refuses_execution_without_explicit_confirmation_flags(self):
        stderr = StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stderr(stderr):
            main(["--execute"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--execute requires --render-dir", stderr.getvalue())

        with tempfile.TemporaryDirectory() as temp_dir:
            stderr = StringIO()
            with self.assertRaises(SystemExit) as raised, redirect_stderr(stderr):
                main(["--execute", "--render-dir", temp_dir])

            self.assertEqual(raised.exception.code, 2)
            self.assertIn("--confirm-mutation", stderr.getvalue())

    def test_execute_runs_preflight_apply_destroy_and_cleanup_with_fake_runner(self):
        calls = []

        def runner(command, cwd):
            calls.append((command, cwd))
            if Path(command[0]).name == "terraform":
                return subprocess.CompletedProcess(command, 0, stdout=f"{command[1]} ok", stderr="")
            if "--display-name" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": [{"id": "read-ok"}]}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = execute_disposable_terraform_validation(
                Path(temp_dir),
                runner=runner,
                env=_resolution_env(temp_dir),
            )

        body = result.to_dict()
        self.assertTrue(body["ok"])
        self.assertEqual(body["target"]["compartmentId"], BARRAGAN_TESTING_COMPARTMENT_ID)
        self.assertEqual(body["target"]["region"], DEFAULT_REGION)
        self.assertEqual(body["mutationStatus"], "destroyed")
        self.assertEqual(body["finalCleanupStatus"], "verified_clean")
        self.assertEqual(
            [
                command["command"][1]
                for command in body["commandsRun"]
                if Path(command["command"][0]).name == "terraform"
            ],
            ["init", "apply", "destroy"],
        )
        self.assertEqual(body["createdResources"][0]["displayName"], VALIDATION_VCN_NAME)
        self.assertEqual(body["destroyedResources"][0]["displayName"], VALIDATION_VCN_NAME)
        self.assertTrue(body["cleanupVerification"]["ok"])
        self.assertEqual(len([call for call in calls if Path(call[0][0]).name == "terraform"]), 3)

    def test_execute_stops_before_mutation_when_preflight_fails(self):
        calls = []

        def runner(command, cwd):
            calls.append((command, cwd))
            if Path(command[0]).name == "terraform":
                self.fail("terraform must not run when preflight fails")
            if "boot-volume" in command:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="NotAuthorizedOrNotFound")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = execute_disposable_terraform_validation(
                Path(temp_dir),
                runner=runner,
                env=_resolution_env(temp_dir),
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertFalse(body["mutation"])
        self.assertEqual(body["mutationStatus"], "preflight_failed")
        self.assertEqual(body["finalCleanupStatus"], "not_started")
        self.assertEqual(body["commandsRun"], [])
        self.assertEqual(len(calls), 2)

    def test_execute_attempts_cleanup_after_apply_failure(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            if [Path(command[0]).name, command[1]] == ["terraform", "apply"]:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="apply failed")
            if Path(command[0]).name == "terraform":
                return subprocess.CompletedProcess(command, 0, stdout=f"{command[1]} ok", stderr="")
            if "--display-name" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            env = _resolution_env(temp_dir)
            result = execute_disposable_terraform_validation(
                Path(temp_dir),
                runner=runner,
                env=env,
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertTrue(body["mutation"])
        self.assertEqual(body["mutationStatus"], "apply_failed")
        self.assertEqual(body["finalCleanupStatus"], "verified_clean")
        self.assertIn(
            [
                env["TERRAFORM_BIN"],
                "destroy",
                "-input=false",
                "-auto-approve",
                "-var",
                f"region={DEFAULT_REGION}",
                "-var",
                f"compartment_ocid={BARRAGAN_TESTING_COMPARTMENT_ID}",
            ],
            calls,
        )

    def test_execute_reports_cleanup_verification_failure(self):
        def runner(command, cwd):
            if Path(command[0]).name == "terraform":
                return subprocess.CompletedProcess(command, 0, stdout=f"{command[1]} ok", stderr="")
            if "--display-name" in command:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    stdout=f'{{"data": [{{"display-name": "{VALIDATION_VCN_NAME}"}}]}}',
                    stderr="",
                )
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = execute_disposable_terraform_validation(
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

    def test_cli_execute_with_fake_runner_confirmation_constant_is_documented(self):
        self.assertEqual(EXECUTION_CONFIRMATION, "mutate-barragan-testing")

    def test_terraform_env_override_takes_precedence_over_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            override_path = _executable(temp_dir, "override-terraform")
            path_dir = Path(temp_dir) / "path"
            path_dir.mkdir()
            _executable(str(path_dir), "terraform")

            resolution = resolve_terraform(
                env={"TERRAFORM_BIN": override_path, "PATH": str(path_dir)}
            )

        self.assertTrue(resolution.ok)
        self.assertEqual(resolution.command, override_path)
        self.assertEqual(resolution.source, "env:TERRAFORM_BIN")

    def test_terraform_path_lookup_precedes_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path_dir = Path(temp_dir) / "path"
            path_dir.mkdir()
            path_terraform = _executable(str(path_dir), "terraform")
            fallback_terraform = _executable(temp_dir, "fallback-terraform")

            resolution = resolve_terraform(
                env={"PATH": str(path_dir)},
                fallback_paths=[fallback_terraform],
            )

        self.assertTrue(resolution.ok)
        self.assertEqual(resolution.command, path_terraform)
        self.assertEqual(resolution.source, "path")

    def test_terraform_uses_executable_fallback_when_path_misses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fallback_terraform = _executable(temp_dir, "fallback-terraform")

            resolution = resolve_terraform(env={"PATH": ""}, fallback_paths=[fallback_terraform])

        self.assertTrue(resolution.ok)
        self.assertEqual(resolution.command, fallback_terraform)
        self.assertEqual(resolution.source, "fallback")

    def test_terraform_command_construction_uses_resolved_binary(self):
        workspace = build_disposable_terraform_workspace()

        commands = build_disposable_execution_commands(
            workspace,
            terraform_executable="/tmp/barragan-test-terraform",
        )

        self.assertEqual([command[0] for command in commands], ["/tmp/barragan-test-terraform"] * 3)

    def test_execute_reports_unresolved_terraform_before_mutation(self):
        calls = []

        def runner(command, cwd):
            calls.append(command)
            if Path(command[0]).name == "terraform":
                self.fail("terraform must not run when Terraform binary is unresolved")
            return subprocess.CompletedProcess(command, 0, stdout='{"data": []}', stderr="")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = execute_disposable_terraform_validation(
                Path(temp_dir),
                runner=runner,
                env={"OCI_CLI_PATH": _executable(temp_dir, "oci"), "PATH": ""},
            )

        body = result.to_dict()
        self.assertFalse(body["ok"])
        self.assertFalse(body["mutation"])
        self.assertEqual(body["mutationStatus"], "terraform_binary_unresolved")
        self.assertIn("TERRAFORM_BIN or TERRAFORM_PATH", body["commandsRun"][0]["stderr"])


if __name__ == "__main__":
    unittest.main()
