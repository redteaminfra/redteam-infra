# Copyright (c) 2026, Oracle and/or its affiliates.
import unittest

from app.domain.job import transition_job_status
from app.jobs.dry_run import run_plan_only_job


class JobStateTests(unittest.TestCase):
    def test_valid_status_transitions(self):
        self.assertEqual(transition_job_status("queued", "running"), "running")
        self.assertEqual(transition_job_status("running", "succeeded"), "succeeded")

    def test_terminal_status_rejects_transition(self):
        with self.assertRaises(ValueError):
            transition_job_status("succeeded", "running")

    def test_dry_run_executor_records_events_and_artifact_ref(self):
        status, events, artifact_refs = run_plan_only_job("deploy_plan")

        self.assertEqual(status, "succeeded")
        self.assertEqual(events[0].message, "job started")
        self.assertIn("dry-run:deploy_plan", artifact_refs)
        self.assertFalse(events[1].data["mutation"])


if __name__ == "__main__":
    unittest.main()
