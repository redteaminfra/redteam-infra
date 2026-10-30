# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.cli.local_workflow import run_local_workflow


ROOT_DIR = Path(__file__).resolve().parents[2]
EXAMPLE_INPUT = ROOT_DIR / "examples" / "standard-rti-input.json"


class LocalWorkflowCliTests(unittest.TestCase):
    def test_local_workflow_runs_persisted_plan_only_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = run_local_workflow(
                database_path=Path(temp_dir) / "barragan.sqlite3",
                input_path=EXAMPLE_INPUT,
                render_dir=Path(temp_dir) / "rendered",
            )

        self.assertEqual(output["engagement"]["status"], "draft")
        self.assertEqual(output["revision"]["status"], "compiled")
        self.assertEqual(output["job"]["status"], "succeeded")
        self.assertEqual(output["plan"]["providerPlan"]["mode"], "dry_run")
        self.assertFalse(output["plan"]["terraformIntent"]["mutation"])
        self.assertIsNotNone(output["plan"]["renderResult"])
        self.assertIn(
            "validation/gates.yaml",
            {artifact["path"] for artifact in output["plan"]["renderResult"]["artifacts"]},
        )

    def test_local_workflow_cli_prints_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "app.cli.local_workflow",
                    "--database",
                    str(Path(temp_dir) / "barragan.sqlite3"),
                    "--input",
                    str(EXAMPLE_INPUT),
                    "--render-dir",
                    str(Path(temp_dir) / "rendered"),
                ],
                check=True,
                cwd=ROOT_DIR / "backend",
                text=True,
                capture_output=True,
            )

        body = json.loads(result.stdout)
        self.assertEqual(body["job"]["artifactRefs"], ["dry-run:deploy_plan"])
        self.assertEqual(body["plan"]["revision"]["status"], "compiled")


if __name__ == "__main__":
    unittest.main()
