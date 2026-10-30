/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

// Controlled UI fixtures: no provider or live application mutations.
for (const unproved of [false, true]) {
  test(`bootstrap timeout requires review with local termination ${unproved ? "unproved" : "proved"}`, async ({ page }) => {
    const chain = {
      engagementId: "eng-timeout", chainId: "proxy01-sea-01", status: "failed", assignedProxy: "proxy01",
      middleProvider: "linode", middleRegion: "us-sea", middleSize: "g6-nanode-1",
      edgeProvider: "linode", edgeRegion: "us-sea", edgeSize: "g6-nanode-1", edgeCount: 1,
      deployJobId: "job-bootstrap", teardownJobId: "", burned: false,
      nodes: [
        { provider: "linode", providerInstanceId: "111", role: "middle", hostname: "middle-fixture", status: "failed" },
        { provider: "linode", providerInstanceId: "112", role: "edge", hostname: "edge-fixture", status: "failed" }
      ]
    };
    const coreJob = {
      id: "job-core", action: "pilot_standard_rti_guarded_execute", status: "succeeded",
      targetType: "engagement", targetId: "eng-timeout", requestedBy: "operator", input: {}, artifactRefs: [],
      events: [{ sequence: 1, level: "info", message: "Core retained", data: {
        mutationStatus: "deployed", ansibleStatus: "configured", finalCleanupStatus: "pending_operator_teardown"
      } }]
    };
    const bootstrapJob = {
      id: "job-bootstrap", action: "linode_sketch_deploy", status: "failed", targetType: "engagement",
      targetId: "eng-timeout", requestedBy: "operator", input: { chainId: chain.chainId }, artifactRefs: [],
      events: [
        { sequence: 1, level: "error", message: "Earlier ordinary bootstrap failure", data: { bootstrap: "failed" } },
        { sequence: 2, level: "error", message: "Local bootstrap execution timed out; remote work may remain; reconciliation required", data: {
          bootstrap: "reconciliation_required", reconciliationRequired: true, timedOut: !unproved, localQuiescenceUnproved: unproved
        } }
      ]
    };
    const mutations: string[] = [];
    await page.route("**/api/**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (!path.startsWith("/api/")) return route.continue();
      if (request.method() !== "GET") {
        mutations.push(`${request.method()} ${path}`);
        return route.abort();
      }
      if (path === "/api/auth/session") return route.fulfill({ json: { authRequired: false } });
      if (path === "/api/templates") return route.fulfill({ json: { templates: [] } });
      if (path === "/api/engagements") return route.fulfill({ json: { engagements: [{
        id: "eng-timeout", name: "Bootstrap timeout fixture", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: "rev-fixture"
      }] } });
      if (path === "/api/jobs") return route.fulfill({ json: { jobs: [] } });
      if (path === "/api/dashboard") return route.fulfill({ json: { dashboard: null } });
      if (path === "/api/health") return route.fulfill({ json: { status: "ok" } });
      if (path.endsWith("/operations")) return route.fulfill({ json: { operations: {
        engagementId: "eng-timeout", housekeepingItems: "",
        lifecycle: { state: "cleanup_required", label: "Needs attention", attentionRequired: true, terminal: false },
        activeJob: coreJob, coreJob, teardownJob: null,
        healthSummary: { status: "attention", hostCount: 1, source: "fixture", stale: false },
        coreInfrastructure: [{ hostname: "homebase-fixture", role: "homebase", status: "deployed", lifecycleState: "active", services: [], health: { status: "healthy" } }],
        sketchInfrastructure: [], providerFindings: [], servicePlacements: [], outboundChannels: [], inboundChannels: [],
        sshConfig: { stanza: "", downloadName: "fixture" }
      } } });
      if (path.endsWith("/sketch-chains")) return route.fulfill({ json: { sketchChains: [chain] } });
      if (path.endsWith("/runs/job-core")) return route.fulfill({ json: { job: coreJob } });
      if (path.endsWith("/jobs/job-bootstrap")) return route.fulfill({ json: { job: bootstrapJob } });
      if (path.endsWith("/readiness")) return route.fulfill({ json: { readiness: {
        target: { name: "barragan-testing", compartmentId: "fixture" }, confirmationToken: "fixture", expectedInstanceDisplayNames: [],
        guardrails: { noTouchCompartments: [] }, sshIngress: { defaultSourceCidrs: [] }, topology: { vcnCidr: "192.168.0.0/16" }
      } } });
      return route.fulfill({ json: {} });
    });
    await page.goto("/");
    await page.getByRole("button", { name: "Infrastructure", exact: true }).click();
    const lifecycle = page.getByRole("region", { name: "Live sketch chain lifecycle", exact: true });
    await expect(lifecycle).toContainText("Remote work may still be running");
    await expect(lifecycle).toContainText("Needs review");
    await expect(lifecycle.getByRole("button", { name: "Retry Bootstrap", exact: true })).toHaveCount(0);
    await expect(lifecycle.getByRole("button", { name: "Deploy New Chain", exact: true })).toHaveCount(0);
    if (unproved) await expect(lifecycle.getByRole("button", { name: "Tear Down Chain", exact: true })).toBeDisabled();
    else await expect(lifecycle.getByRole("button", { name: "Tear Down Chain", exact: true })).toBeEnabled();
    for (const width of [760, 1280]) {
      await page.setViewportSize({ width, height: 1000 });
      await lifecycle.locator(".sketch-chain-card").first().evaluate((element) => element.scrollIntoView({ block: "start" }));
      expect(await lifecycle.evaluate(e => e.scrollWidth <= e.clientWidth + 1)).toBe(true);
      await page.screenshot({ path: test.info().outputPath(`bootstrap-${unproved ? "unproved" : "timeout"}-${width}.png`) });
    }
    expect(mutations).toEqual([]);
  });
}
