# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from app.cli.plan_only import main


class PlanOnlyCliTests(unittest.TestCase):
    def test_cli_outputs_plan_and_writes_artifacts(self):
        with tempfile.TemporaryDirectory() as render_dir:
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["--engagement-id", "eng-cli-test", "--render-dir", render_dir])

            self.assertEqual(exit_code, 0)
            body = json.loads(stdout.getvalue())
            self.assertEqual(body["revision"]["status"], "compiled")
            self.assertIsNotNone(body["renderResult"])
            self.assertTrue((Path(body["renderResult"]["root"]) / "manifest.yaml").exists())
            self.assertEqual(body["providerPreflight"]["status"], "not_run")
            self.assertFalse(body["deployReadiness"]["ready"])
            self.assertFalse(body["terraformIntent"]["mutation"])


if __name__ == "__main__":
    unittest.main()
