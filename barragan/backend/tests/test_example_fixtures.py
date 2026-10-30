# Copyright (c) 2026, Oracle and/or its affiliates.
import json
import tempfile
import unittest
from pathlib import Path

from app.services.access_plans import PlatformAccessUser
from app.services.catalog import validate_template_input
from app.services.deployment_orchestrator import plan_standard_rti_deployment


EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "examples"
STANDARD_RTI_INPUT = EXAMPLES_DIR / "standard-rti-input.json"


class ExampleFixtureTests(unittest.TestCase):
    def test_standard_rti_example_validates_against_catalog(self):
        payload = _load_standard_rti_input()

        result = validate_template_input("standard-rti", payload)

        self.assertTrue(result.valid)
        self.assertEqual(result.normalized["engagementName"], "of02-dev-example")

    def test_standard_rti_example_runs_plan_only_orchestrator(self):
        payload = _load_standard_rti_input()
        access_users = [
            PlatformAccessUser(
                user_id="user-example-operator",
                username="operator",
                credential_ref="secret://users/operator",
                privileges=["view", "operate"],
            )
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            result = plan_standard_rti_deployment(
                engagement_id="eng-example-fixture",
                input_parameters=payload,
                access_users=access_users,
                render_destination=Path(temp_dir),
            )

        body = result.to_dict()
        self.assertEqual(body["revision"]["status"], "compiled")
        self.assertEqual(body["providerPlan"]["mode"], "dry_run")
        self.assertFalse(body["terraformIntent"]["mutation"])
        targets = {target["hostGroupId"]: target for target in body["accessPlan"]["targets"]}
        self.assertEqual(targets["homebase"]["users"][0]["username"], "operator")


def _load_standard_rti_input() -> dict:
    with STANDARD_RTI_INPUT.open("r", encoding="utf-8") as handle:
        return json.load(handle)


if __name__ == "__main__":
    unittest.main()
