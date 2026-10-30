# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.services.lifecycle_plans import plan_archive, plan_replace_edge, plan_route_repair
from app.services.revision_compiler import compile_standard_rti_revision
from tests.test_catalog_service import valid_standard_rti_payload


class LifecyclePlanTests(unittest.TestCase):
    def test_replace_edge_plan_covers_repair_workflow(self):
        revision = compile_standard_rti_revision("eng-life-test", valid_standard_rti_payload())
        plan = plan_replace_edge(revision, "ingress-01", "linode").to_dict()

        steps = [step["step"] for step in plan["steps"]]
        self.assertEqual(plan["mode"], "dry_run")
        self.assertIn("plan_replacement_edge", steps)
        self.assertIn("plan_dns_and_certificate_cutover", steps)
        self.assertIn("plan_proxy_route_rewire", steps)
        self.assertIn("plan_egress_profile_republish", steps)
        self.assertIn("plan_old_edge_teardown", steps)
        republish_step = next(step for step in plan["steps"] if step["step"] == "plan_egress_profile_republish")
        self.assertEqual(republish_step["egressProfiles"][0]["publicationPath"], "/opt/proxy01/default-sketch-egress-socks5.conf")
        self.assertFalse(any(step["mutation"] for step in plan["steps"]))

    def test_route_repair_plan_uses_management_path(self):
        revision = compile_standard_rti_revision("eng-life-test", valid_standard_rti_payload())
        plan = plan_route_repair(revision, "egress-01").to_dict()

        validation_step = plan["steps"][-1]
        republish_step = plan["steps"][1]
        self.assertEqual(republish_step["egressProfile"]["listenerPort"], 3333)
        self.assertEqual(validation_step["step"], "plan_path_validation")
        self.assertIn("homebase", validation_step["managementPath"])

    def test_archive_plan_preserves_required_refs(self):
        revision = compile_standard_rti_revision("eng-life-test", valid_standard_rti_payload())
        plan = plan_archive(revision, ["manifest.yaml", "topology.yaml"]).to_dict()

        self.assertEqual(plan["action"], "archive_engagement")
        self.assertEqual(plan["preservedRefs"]["revisionId"], revision.id)
        self.assertEqual(plan["preservedRefs"]["artifactRefs"], ["manifest.yaml", "topology.yaml"])
        self.assertFalse(any(step["mutation"] for step in plan["steps"]))


if __name__ == "__main__":
    unittest.main()
