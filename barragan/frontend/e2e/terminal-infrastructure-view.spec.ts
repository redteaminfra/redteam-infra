/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

// Mocked UI fixtures only: these tests never provision or contact providers.
for (const state of ["destroyed", "active", "cleanup_required", "deploying"] as const) {
  test(`Infrastructure respects canonical ${state} lifecycle over retained history`, async ({ page }) => {
    const requests: string[] = [];
    const recovering = state === "cleanup_required";
    const deploying = state === "deploying";
    const coreJob = {
      id: "job-core", action: "pilot_standard_rti_guarded_execute", status: deploying ? "running" : "succeeded",
      targetType: "engagement", targetId: "eng-history", input: { engagementId: "eng-history" },
      requestedBy: "operator", artifactRefs: [], events: deploying ? [] : [{ sequence: 1, level: "info", message: "Historical deployment output", data: {
        mutationStatus: "deployed", ansibleStatus: "configured", finalCleanupStatus: "pending_operator_teardown"
      } }]
    };
    const cleanupJob = {
      id: "job-cleanup", action: "engagement_comprehensive_teardown", status: recovering ? "failed" : "succeeded",
      targetType: "engagement", targetId: "eng-history", input: { engagementId: "eng-history", coreJobId: "job-core", scopeSnapshot: {
        engagementId: "eng-history", coreJobId: "job-core", snapshotId: "snapshot-history", confirmationPhrase: "teardown-history",
        chains: [], ownedProviderRecordIds: [], excludedUnmanagedProviderRecords: [], publicVerificationTargets: [],
        core: { jobId: "job-core", workspace: "/tmp/fixture", proxyCount: 0 },
        inspector: { tracked: false, ownedProviderRecordIds: [], recordOwners: {}, verificationTargetCount: 0 }
      } },
      requestedBy: "operator", artifactRefs: [], events: [{ sequence: 1, level: recovering ? "error" : "info", message: "Cleanup result", data: {
        finalCleanupStatus: recovering ? "cleanup_not_verified" : "verified_clean"
      } }]
    };
    const operations = {
      engagementId: "eng-history", housekeepingItems: "",
      lifecycle: { state, label: state, terminal: state === "destroyed", attentionRequired: recovering, evidence: deploying ? [{ kind: "core_job", id: "job-core", status: "running" }] : [] },
      activeJob: coreJob, coreJob,
      teardownJob: { ...cleanupJob, recoveryState: recovering ? "recoverable" : "complete" },
      healthSummary: { status: "healthy", hostCount: 1, source: "fixture", lastCheckedAt: null, stale: false, detail: "" },
      // Deliberately stale retained host for destroyed; new deploying generation has no hosts yet.
      coreInfrastructure: deploying ? [] : [{ hostname: "homebase-history", role: "homebase", status: "deployed", lifecycleState: "active", services: [], health: { status: "healthy" } }],
      sketchInfrastructure: [], providerFindings: [], servicePlacements: [], outboundChannels: [], inboundChannels: [],
      sshConfig: { stanza: "", downloadName: "history-ssh-config" }
    };
    await page.route("**/api/**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (!path.startsWith("/api/")) return route.continue();
      requests.push(`${request.method()} ${path}`);
      if (request.method() !== "GET") throw new Error(`Unexpected mutation: ${request.method()} ${path}`);
      if (path === "/api/auth/session") return route.fulfill({ json: { authRequired: false } });
      if (path === "/api/templates") return route.fulfill({ json: { templates: [] } });
      if (path === "/api/engagements") return route.fulfill({ json: { engagements: [{ id: "eng-history", name: "History fixture", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: "rev-1" }] } });
      if (path === "/api/jobs") return route.fulfill({ json: { jobs: [] } });
      if (path === "/api/dashboard") return route.fulfill({ json: { dashboard: null } });
      if (path === "/api/health") return route.fulfill({ json: { status: "ok" } });
      if (path.endsWith("/operations")) return route.fulfill({ json: { operations } });
      if (path.endsWith("/sketch-chains")) return route.fulfill({ json: { sketchChains: [] } });
      if (path.endsWith("/runs/job-core")) return route.fulfill({ json: { job: coreJob } });
      if (path.endsWith("/runs/job-cleanup")) return route.fulfill({ json: { job: cleanupJob } });
      if (path.endsWith("/readiness")) return route.fulfill({ json: { readiness: {
        target: { name: "barragan-testing", compartmentId: "fixture" }, confirmationToken: "fixture", expectedInstanceDisplayNames: [],
        guardrails: { noTouchCompartments: [] }, sshIngress: { defaultSourceCidrs: [] }, topology: { vcnCidr: "192.168.0.0/16" }
      } } });
      return route.fulfill({ json: {} });
    });
    await page.goto("/");
    await page.getByRole("button", { name: "Infrastructure", exact: true }).click();
    if (state === "destroyed") {
      await expect(page.getByRole("heading", { name: "Infrastructure Destroyed", exact: true })).toBeVisible();
      const history = page.getByRole("region", { name: "Historical core infrastructure", exact: true });
      await expect(history).toContainText("job-core");
      await expect(history).toContainText("pending_operator_teardown");
      await expect(history).toContainText("before verified cleanup");
      await expect(page.getByRole("region", { name: "Manage running infrastructure", exact: true })).toHaveCount(0);
      await expect(page.getByRole("region", { name: "Live sketch chain lifecycle", exact: true })).toHaveCount(0);
      for (const name of ["Tear Down Infrastructure", "Retry Tear Down", "Start Instances", "Stop Instances", "Re-Deploy Core Infrastructure", "Prepare Infrastructure Plan", "Deploy"]) {
        await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
      }
      await history.getByRole("button", { name: "Refresh", exact: true }).click();
      await expect(history).toBeVisible();
      await page.getByRole("button", { name: "History", exact: true }).click();
      await expect(page.getByRole("region", { name: "Core deployment history", exact: true })).toContainText("Historical deployment output");
    } else if (recovering) {
      await expect(page.getByRole("heading", { name: "Recover Infrastructure Cleanup", exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Retry Tear Down", exact: true })).toBeEnabled();
      await expect(page.getByRole("region", { name: "Live sketch chain lifecycle", exact: true })).toHaveCount(0);
    } else {
      await expect(page.getByRole("heading", { name: deploying ? "Deploying Infrastructure" : "Manage Running Infrastructure", exact: true })).toBeVisible();
      await expect(page.getByRole("region", { name: "Current core infrastructure", exact: true })).toContainText("job-core");
      await expect(page.getByRole("heading", { name: "Infrastructure Destroyed", exact: true })).toHaveCount(0);
    }
    expect(requests.every((request) => request.startsWith("GET "))).toBe(true);
  });
}
