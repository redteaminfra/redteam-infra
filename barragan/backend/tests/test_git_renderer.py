# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import tempfile
import unittest
from pathlib import Path

from app.services.git_renderer import render_revision_plan
from app.services.revision_compiler import compile_standard_rti_revision
from tests.test_catalog_service import valid_standard_rti_payload


class GitRendererTests(unittest.TestCase):
    def test_renders_standard_rti_revision_artifacts_deterministically(self):
        revision = compile_standard_rti_revision("eng-render-test", valid_standard_rti_payload())

        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first = render_revision_plan(revision, Path(first_dir), "job-render-test")
            second = render_revision_plan(revision, Path(second_dir), "job-render-test")

            first_artifacts = [artifact.to_dict() for artifact in first.artifacts]
            second_artifacts = [artifact.to_dict() for artifact in second.artifacts]

            self.assertEqual(first_artifacts, second_artifacts)
            artifact_paths = {artifact["path"] for artifact in first_artifacts}
            self.assertIn("topology.yaml", artifact_paths)
            self.assertIn("validation/gates.yaml", artifact_paths)
            self.assertIn("terraform/core.tf.json", artifact_paths)
            self.assertIn("ansible/inventory.yaml", artifact_paths)
            self.assertIn("proxy/egress-profiles.yaml", artifact_paths)
            self.assertIn("proxy/profile-files.yaml", artifact_paths)
            self.assertIn("proxy/ingress-routes.yaml", artifact_paths)
            self.assertIn("proxy/reverse-channels.yaml", artifact_paths)

            manifest = json.loads((Path(first.root) / "manifest.yaml").read_text(encoding="utf-8"))
            validation = json.loads((Path(first.root) / "validation" / "gates.yaml").read_text(encoding="utf-8"))
            sketch_terraform = json.loads((Path(first.root) / "terraform" / "sketch.tf.json").read_text(encoding="utf-8"))
            profile_files = json.loads((Path(first.root) / "proxy" / "profile-files.yaml").read_text(encoding="utf-8"))
            self.assertFalse("private_key" in json.dumps(manifest).lower())
            self.assertEqual(manifest["non_mutation_notice"].split(";")[0], "render-only")
            self.assertEqual(manifest["validation_gate_summary"], {"total": 6, "passed": 6, "failed": 0, "blockers": 0})
            self.assertEqual(validation["summary"], manifest["validation_gate_summary"])
            self.assertEqual(validation["gates"][-1]["id"], "plan-only-intent")
            self.assertEqual(sketch_terraform["linode"][0]["attributes"]["terraformVariables"]["middle_region"], "us-sea")
            self.assertEqual(sketch_terraform["digitalocean"][0]["attributes"]["terraformVariables"]["edge_regions"], ["sfo3"])
            self.assertNotIn("linode-token-sensitive-value", json.dumps(sketch_terraform))
            self.assertNotIn("do-token-sensitive-value", json.dumps(sketch_terraform))
            self.assertEqual(profile_files[0]["publicationPath"], "/opt/proxy01/default-sketch-egress-socks5.conf")


if __name__ == "__main__":
    unittest.main()
