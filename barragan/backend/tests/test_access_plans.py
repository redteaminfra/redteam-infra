# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.services.access_plans import PlatformAccessUser, plan_access_propagation
from app.services.revision_compiler import compile_standard_rti_revision
from tests.test_catalog_service import valid_standard_rti_payload


class AccessPlanTests(unittest.TestCase):
    def test_named_operator_targets_core_only_by_default(self):
        revision = compile_standard_rti_revision("eng-access-test", valid_standard_rti_payload())
        user = PlatformAccessUser("user-1", "alice", "secret://users/alice", ["view", "operate"])

        plan = plan_access_propagation(revision, [user]).to_dict()
        targets = {target["hostGroupId"]: target for target in plan["targets"]}

        self.assertEqual(targets["homebase"]["accessKind"], "core_named")
        self.assertNotIn("proxy", targets)
        self.assertEqual(targets["middle-chain-1"]["accessKind"], "sketch_management")
        self.assertIsNone(targets["edge-chain-1"]["users"][0]["platformUserId"])
        self.assertFalse(any(step["mutation"] for step in plan["steps"]))

    def test_proxy_core_access_is_explicit(self):
        revision = compile_standard_rti_revision("eng-access-test", valid_standard_rti_payload())
        user = PlatformAccessUser("user-1", "alice", "secret://users/alice", ["view", "operate"])

        plan = plan_access_propagation(revision, [user], allow_proxy_ssh=True).to_dict()
        targets = {target["hostGroupId"]: target for target in plan["targets"]}

        self.assertEqual(targets["proxy"]["accessKind"], "core_named")
        self.assertEqual(targets["proxy"]["users"][0]["username"], "alice")


if __name__ == "__main__":
    unittest.main()
