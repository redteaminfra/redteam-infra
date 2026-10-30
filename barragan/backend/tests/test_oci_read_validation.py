# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from app.cli.oci_read_validate import main
from app.integrations.oci_read_validation import (
    BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID,
    BARRAGAN_TESTING_COMPARTMENT_ID,
    OciDevelopmentTarget,
    OciSafetyError,
    build_read_checks,
    resolve_oci_cli,
    run_read_validation,
    validate_barragan_testing_target,
)


def _executable(directory: str, name: str) -> str:
    path = Path(directory) / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


class OciReadValidationTests(unittest.TestCase):
    def test_builds_only_read_only_commands_for_barragan_testing(self):
        checks = build_read_checks(OciDevelopmentTarget())

        self.assertEqual([check.id for check in checks], ["oci.core.vcn.list", "oci.core.boot-volume.list"])
        for check in checks:
            self.assertIn("--auth", check.command)
            self.assertIn("instance_principal", check.command)
            self.assertIn("--compartment-id", check.command)
            self.assertIn(BARRAGAN_TESTING_COMPARTMENT_ID, check.command)
            self.assertIn("--output", check.command)
            self.assertNotIn("create", check.command)
            self.assertNotIn("delete", check.command)
            self.assertNotIn("update", check.command)

    def test_rejects_no_touch_and_non_testing_compartments(self):
        with self.assertRaises(OciSafetyError):
            validate_barragan_testing_target(BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID, "RedTeam")
        with self.assertRaises(OciSafetyError):
            validate_barragan_testing_target(BARRAGAN_TESTING_COMPARTMENT_ID, "RedTeam-1")
        with self.assertRaises(OciSafetyError):
            validate_barragan_testing_target("ocid1.compartment.oc1..other", "other")

    def test_runs_read_checks_with_injected_runner(self):
        commands = []

        def runner(command):
            commands.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"data": [{"id": "one"}, {"id": "two"}]}),
                stderr="",
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            oci_path = _executable(temp_dir, "oci")
            result = run_read_validation(runner=runner, env={"OCI_CLI_PATH": oci_path, "PATH": ""})

        self.assertTrue(result.ok)
        self.assertEqual([check.count for check in result.checks], [2, 2])
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][0], oci_path)
        self.assertFalse(result.to_dict()["mutation"])
        self.assertEqual(result.to_dict()["commandResolution"]["command"], oci_path)
        self.assertEqual(result.to_dict()["commandResolution"]["source"], "env:OCI_CLI_PATH")

    def test_failed_oci_command_marks_validation_failed(self):
        def runner(command):
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="NotAuthorizedOrNotFound")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_read_validation(
                runner=runner,
                env={"OCI_CLI_PATH": _executable(temp_dir, "oci"), "PATH": ""},
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.checks[0].error, "NotAuthorizedOrNotFound")

    def test_runner_os_error_marks_validation_failed(self):
        def runner(command):
            raise PermissionError("Operation not permitted")

        with tempfile.TemporaryDirectory() as temp_dir:
            result = run_read_validation(
                runner=runner,
                env={"OCI_CLI_PATH": _executable(temp_dir, "oci"), "PATH": ""},
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.checks[0].error, "Operation not permitted")

    def test_oci_cli_env_override_takes_precedence_over_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            override_path = _executable(temp_dir, "override-oci")
            path_dir = Path(temp_dir) / "path"
            path_dir.mkdir()
            _executable(str(path_dir), "oci")

            resolution = resolve_oci_cli(
                env={"OCI_CLI_PATH": override_path, "PATH": str(path_dir)}
            )

        self.assertTrue(resolution.ok)
        self.assertEqual(resolution.command, override_path)
        self.assertEqual(resolution.source, "env:OCI_CLI_PATH")

    def test_oci_cli_path_lookup_precedes_fallback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path_dir = Path(temp_dir) / "path"
            path_dir.mkdir()
            path_oci = _executable(str(path_dir), "oci")
            fallback_oci = _executable(temp_dir, "fallback-oci")

            resolution = resolve_oci_cli(
                env={"PATH": str(path_dir)},
                fallback_paths=[fallback_oci],
            )

        self.assertTrue(resolution.ok)
        self.assertEqual(resolution.command, path_oci)
        self.assertEqual(resolution.source, "path")

    def test_oci_cli_uses_executable_fallback_when_path_misses(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fallback_oci = _executable(temp_dir, "fallback-oci")

            resolution = resolve_oci_cli(env={"PATH": ""}, fallback_paths=[fallback_oci])

        self.assertTrue(resolution.ok)
        self.assertEqual(resolution.command, fallback_oci)
        self.assertEqual(resolution.source, "fallback")

    def test_unresolved_oci_cli_reports_override_variable_without_running(self):
        def runner(command):
            self.fail("OCI read validation must not run commands when OCI CLI is unresolved")

        result = run_read_validation(
            runner=runner,
            env={"OCI_CLI_PATH": "/tmp/barragan-missing-oci", "PATH": ""},
        )

        self.assertFalse(result.ok)
        self.assertIn("Could not resolve OCI CLI executable", result.checks[0].error)
        self.assertIn("OCI_CLI_PATH", result.checks[0].error)
        self.assertFalse(result.to_dict()["commandResolution"]["ok"])
        self.assertIn("OCI_CLI_PATH", result.to_dict()["commandResolution"]["error"])

    def test_cli_print_commands_uses_resolved_oci_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            oci_path = _executable(temp_dir, "oci")
            stdout = StringIO()
            with patch.dict(os.environ, {"OCI_CLI_PATH": oci_path, "PATH": ""}, clear=True):
                with redirect_stdout(stdout):
                    exit_code = main(["--print-commands", "--pretty"])

        body = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(body["commandResolution"]["command"], oci_path)
        self.assertEqual(body["commandResolution"]["source"], "env:OCI_CLI_PATH")
        self.assertEqual(body["checks"][0]["command"][0], oci_path)


if __name__ == "__main__":
    unittest.main()
