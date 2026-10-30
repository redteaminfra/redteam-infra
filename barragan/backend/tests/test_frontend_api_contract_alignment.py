# Copyright (c) 2026, Oracle and/or its affiliates.
import re
import unittest
from pathlib import Path


CLIENT_PATH = Path(__file__).resolve().parents[2] / "frontend" / "src" / "api" / "client.ts"


class FrontendApiContractAlignmentTests(unittest.TestCase):
    def test_frontend_client_exposes_required_contract_paths(self):
        client_source = CLIENT_PATH.read_text(encoding="utf-8")
        required_literals = [
            "/api/health",
            "/api/dashboard",
            "/api/templates",
            "/api/credentials",
            "/api/engagements",
            "/api/jobs",
            "/api/orchestrator/standard-rti/plan",
            "/api/orchestrator/barragan-testing/disposable/readiness",
            "/api/orchestrator/barragan-testing/disposable/run",
            "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness",
            "/api/orchestrator/barragan-testing/pilot-standard-rti/run",
            "/api/orchestrator/barragan-testing/pilot-standard-rti/runs",
            "/api/orchestrator/barragan-testing/linode-sketch/runs",
            "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs",
            "/api/provider-catalog/sketch/region-policies",
            "/api/provider-catalog/sketch/digitalocean/preflight",
        ]
        required_patterns = [
            r"/api/templates/\$\{templateId\}",
            r"/api/templates/\$\{templateId\}/validate",
            r"/api/credentials/\$\{credentialId\}/validate",
            r"/api/credentials/\$\{credentialId\}",
            r"/api/engagements/\$\{engagementId\}",
            r"/api/engagements/\$\{engagementId\}/inbound-channels/\$\{channelId\}/apply-preview",
            r"/api/engagements/\$\{engagementId\}/inbound-channels/\$\{channelId\}/apply",
            r"/api/engagements/\$\{engagementId\}/inbound-channels/\$\{channelId\}/validate",
            r"/api/engagements/\$\{engagementId\}/sketch-chains/\$\{chainId\}/stop",
            r"/api/engagements/\$\{engagementId\}/sketch-chains/\$\{chainId\}/start",
            r"/api/engagements/\$\{engagementId\}/archive",
            r"/api/engagements/\$\{engagementId\}/infrastructure",
            r"/api/engagements/\$\{engagementId\}/revisions",
            r"/api/revisions/\$\{revisionId\}",
            r"/api/revisions/\$\{revisionId\}/render",
            r"/api/jobs/\$\{jobId\}",
            r"/api/jobs/\$\{jobId\}/run",
            r"/api/orchestrator/barragan-testing/pilot-standard-rti/runs/\$\{jobId\}",
            r"/api/orchestrator/barragan-testing/linode-sketch/runs/\$\{jobId\}",
            r"/api/orchestrator/barragan-testing/linode-sketch/runs/\$\{jobId\}/teardown",
            r"/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs/\$\{jobId\}",
            r"/api/provider-catalog/sketch/region-policies/\$\{encodeURIComponent\(provider\)\}",
        ]

        for literal in required_literals:
            self.assertIn(literal, client_source)
        for pattern in required_patterns:
            self.assertRegex(client_source, pattern)

    def test_frontend_client_uses_post_for_mutations(self):
        client_source = CLIENT_PATH.read_text(encoding="utf-8")
        mutation_methods = [
            "validateTemplate",
            "createCredential",
            "validateCredential",
            "createEngagement",
            "archiveEngagement",
            "configureEngagementInfrastructure",
            "createRevision",
            "renderRevision",
            "createJob",
            "runJob",
            "planStandardRti",
            "digitalOceanSketchPreflight",
            "runBarraganTestingDisposableDeployment",
            "runBarraganTestingPilotStandardRti",
            "startBarraganTestingPilotStandardRtiRun",
            "startBarraganTestingLinodeSketchRun",
            "teardownBarraganTestingLinodeSketchRun",
            "startBarraganTestingDigitalOceanSketchValidationRun",
        ]

        for method in mutation_methods:
            self.assertRegex(client_source, rf"{method}: [\s\S]*?postJson")

    def test_frontend_client_uses_patch_and_delete_for_engagement_metadata(self):
        client_source = CLIENT_PATH.read_text(encoding="utf-8")
        self.assertRegex(client_source, r"updateEngagement: [\s\S]*?patchJson")
        self.assertRegex(client_source, r"rotateCredential: [\s\S]*?patchJson")
        self.assertRegex(client_source, r"deleteEngagement: [\s\S]*?deleteJson")
        self.assertRegex(client_source, r"deleteCredential: [\s\S]*?deleteJson")


if __name__ == "__main__":
    unittest.main()
