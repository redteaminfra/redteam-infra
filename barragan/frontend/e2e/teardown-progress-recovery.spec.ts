/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-zy01";

test("sketch teardown opens a closable and reopenable progress console", async ({ page }) => {
  await mockSketchTeardownApi(page);
  await page.goto("/");
  await expect(page.getByText("ready")).toBeVisible();
  await page.getByRole("button", { name: "Infrastructure" }).click();

  const lifecycle = page.getByRole("region", { name: "Live sketch chain lifecycle" });
  await expect(lifecycle).toContainText("proxy01-sea-01");
  await lifecycle.getByRole("button", { name: "Tear Down Chain" }).click();
  await lifecycle.getByLabel("proxy01-sea-01 teardown phrase").fill("teardown-proxy01-sea-01");
  await lifecycle.getByRole("button", { name: "Confirm Chain Tear Down" }).click();

  const consolePanel = page.getByRole("region", { name: "Sketch teardown progress" });
  await expect(consolePanel).toContainText("terraform cleanup verified");
  await page.screenshot({ path: "../.playwright-cli/wi0184-sketch-teardown-console.png", fullPage: true });
  await consolePanel.getByRole("button", { name: "Close" }).click();
  await expect(consolePanel).toHaveCount(0);
  await lifecycle.getByRole("button", { name: "Log" }).click();
  await expect(page.getByRole("region", { name: "Sketch teardown progress" })).toContainText("job-sketch-teardown");
});

test("incomplete chain state links directly to Provider Tracking", async ({ page }) => {
  await mockDriftApi(page);
  await page.goto("/");
  await expect(page.getByText("ready")).toBeVisible();
  await page.getByRole("button", { name: "Infrastructure" }).click();

  await expect(page.getByText("Provider inventory still sees infrastructure for this engagement")).toBeVisible();
  await page.getByRole("button", { name: "Review Provider Recovery" }).click();
  await expect(page.getByRole("region", { name: "Provider tracking findings" })).toContainText("edge-zy01");
  await page.screenshot({ path: "../.playwright-cli/wi0184-provider-drift-recovery.png", fullPage: true });
});

test("provider recovery opens a closable and reopenable progress console", async ({ page }) => {
  await mockProviderRecoveryApi(page);
  await page.goto("/");
  await expect(page.getByText("ready")).toBeVisible();

  const tracking = page.locator('[aria-label="Provider orphan candidates"]');
  await tracking.getByRole("button", { name: "Teardown Plan" }).click();
  await tracking.getByLabel("Live teardown confirmation for edge-zy01").fill("tear-down-linode-instance-123");
  await tracking.getByRole("button", { name: "Confirm Teardown" }).click();

  const consolePanel = page.getByRole("region", { name: "Provider recovery progress" });
  await expect(consolePanel).toContainText("provider resource delete requested");
  await consolePanel.getByRole("button", { name: "Close" }).click();
  await expect(consolePanel).toHaveCount(0);
  await page.getByRole("button", { name: "Log" }).click();
  await expect(page.getByRole("region", { name: "Provider recovery progress" })).toContainText("job-provider-teardown");
});

async function mockSketchTeardownApi(page: Page) {
  let chain = deployedChain();
  await baseApi(page, async (pathname, method) => {
    if (pathname === `/api/engagements/${engagementId}/sketch-chains/${chain.chainId}/teardown` && method === "POST") {
      chain = { ...chain, status: "tearing_down", teardownJobId: "job-sketch-teardown" };
      return { chain, job: sketchTeardownJob("running") };
    }
    if (pathname === "/api/jobs/job-sketch-teardown") return { job: sketchTeardownJob("succeeded") };
    if (pathname === `/api/engagements/${engagementId}/sketch-chains/${chain.chainId}/refresh` && method === "POST") {
      chain = { ...chain, status: "destroyed", nodes: [] };
      return { sketchChain: chain };
    }
    if (pathname === `/api/engagements/${engagementId}/sketch-chains`) return { sketchChains: [chain] };
    return null;
  });
}

async function mockDriftApi(page: Page) {
  const finding = providerFinding();
  await baseApi(page, async (pathname) => {
    if (pathname === `/api/engagements/${engagementId}/sketch-chains`) {
      return { sketchChains: [{ ...deployedChain(), status: "deploying", nodes: [] }] };
    }
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      return { operations: operationsOverview([finding]) };
    }
    return null;
  });
}

async function mockProviderRecoveryApi(page: Page) {
  let actionCount = 0;
  await baseApi(page, async (pathname, method) => {
    if (pathname === "/api/dashboard") {
      return { dashboard: { ...emptyDashboard(), orphanCandidates: [providerFinding()], reconciliation: { status: "provider-reconciled", detail: "One owned provider resource requires recovery." } } };
    }
    if (pathname === "/api/dashboard/orphan-candidates/actions" && method === "POST") {
      actionCount += 1;
      return actionCount === 1
        ? { candidate: providerFinding(), status: "planned", confirmationToken: "tear-down-linode-instance-123", job: providerRecoveryJob("succeeded", true) }
        : { candidate: providerFinding(), status: "running", confirmationToken: "tear-down-linode-instance-123", job: providerRecoveryJob("running", false) };
    }
    if (pathname === "/api/jobs/job-provider-teardown") {
      return { job: providerRecoveryJob("succeeded", false) };
    }
    return null;
  });
}

async function baseApi(
  page: Page,
  custom: (pathname: string, method: string) => Promise<Record<string, unknown> | null>
) {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const response = await custom(pathname, request.method());
    if (response) return route.fulfill({ json: response });
    if (pathname === "/api/templates") return route.fulfill({ json: { templates: [] } });
    if (pathname === "/api/engagements") return route.fulfill({ json: { engagements: [engagementSummary()] } });
    if (pathname === "/api/jobs") return route.fulfill({ json: { jobs: [pilotJobSummary()] } });
    if (pathname === "/api/dashboard") return route.fulfill({ json: { dashboard: emptyDashboard() } });
    if (pathname === "/api/health") return route.fulfill({ json: { service: "barragan-api", status: "ok" } });
    if (pathname === "/api/provider-catalog/sketch") return route.fulfill({ json: { catalog: providerCatalog() } });
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness") {
      return route.fulfill({ json: { readiness: readiness() } });
    }
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001") {
      return route.fulfill({ json: { job: pilotJob() } });
    }
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      return route.fulfill({ json: { operations: operationsOverview([]) } });
    }
    return route.fulfill({ json: {} });
  });
}

function engagementSummary() {
  return { id: engagementId, name: "ZY01", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: "rev-1" };
}

function pilotJobSummary() {
  return { id: "job-pilot-001", action: "pilot_standard_rti_guarded_execute", status: "succeeded", target: "ZY01", createdAt: "2026-07-08T18:00:00Z" };
}

function pilotJob() {
  return {
    id: "job-pilot-001",
    action: "pilot_standard_rti_guarded_execute",
    status: "succeeded",
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId, engagementName: "ZY01" },
    artifactRefs: [],
    events: [{ sequence: 1, level: "info", message: "pilot deployment ready", data: { mutationStatus: "deployed", finalCleanupStatus: "pending_operator_teardown" } }]
  };
}

function deployedChain() {
  return {
    chainId: "proxy01-sea-01",
    engagementId,
    assignedProxy: "proxy01",
    middleProvider: "linode",
    middleRegion: "us-sea",
    middleSize: "g6-nanode-1",
    edgeProvider: "linode",
    edgeRegion: "us-sea",
    edgeSize: "g6-nanode-1",
    status: "deployed",
    burned: false,
    burnedNote: "",
    deployJobId: "job-linode-deploy",
    teardownJobId: "",
    terraformWorkingDirectory: "/tmp/sketch",
    nodes: [{ provider: "linode", providerInstanceId: "123", role: "edge", hostname: "edge-zy01", status: "deployed" }],
    createdAt: "2026-07-08T18:00:00Z",
    updatedAt: "2026-07-08T18:00:00Z"
  };
}

function sketchTeardownJob(status: "running" | "succeeded") {
  return {
    id: "job-sketch-teardown",
    action: "linode_sketch_teardown",
    status,
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId, chainId: "proxy01-sea-01" },
    artifactRefs: [],
    events: status === "running"
      ? [{ sequence: 1, level: "info", message: "Linode sketch teardown started", data: {} }]
      : [
          { sequence: 1, level: "info", message: "Linode sketch teardown started", data: {} },
          { sequence: 2, level: "info", message: "terraform destroy completed", data: { phase: "destroy" } },
          { sequence: 3, level: "info", message: "terraform cleanup verified", data: { phase: "cleanup", cleanupVerified: true } }
        ]
  };
}

function operationsOverview(providerFindings: Array<Record<string, unknown>>) {
  return {
    engagementId,
    housekeepingItems: "",
    activeJob: pilotJobSummary(),
    healthSummary: { status: "healthy", hostCount: 1, activeHostCount: 1, source: "test", lastCheckedAt: "2026-07-08T18:00:00Z", stale: false, detail: "" },
    coreInfrastructure: [{
      hostname: "homebase-zy01",
      role: "homebase",
      status: "active",
      lifecycleState: "active",
      publicIp: "",
      privateIp: "10.0.0.10",
      region: "us-sanjose-1",
      compartment: "barragan-testing",
      services: ["SSH"],
      health: { status: "healthy", source: "test", lastCheckedAt: "2026-07-08T18:00:00Z", stale: false, detail: "" }
    }],
    sketchInfrastructure: [],
    providerFindings,
    servicePlacements: [],
    outboundChannels: [],
    inboundChannels: [],
    sshConfig: { stanza: "", downloadName: "zy01-ssh-config" }
  };
}

function providerFinding() {
  return {
    candidateId: "linode:instance:123",
    engagementId,
    engagementName: "ZY01",
    provider: "linode",
    resourceType: "instance",
    resourceId: "123",
    name: "edge-zy01",
    region: "us-sea",
    lifecycleState: "running",
    reason: "Barragan-owned provider resource has incomplete local chain state.",
    actions: ["track", "tear_down"],
    metadata: { barraganOwned: true }
  };
}

function providerRecoveryJob(status: "running" | "succeeded", plan: boolean) {
  return {
    id: plan ? "job-provider-plan" : "job-provider-teardown",
    action: plan ? "provider_orphan_teardown_plan" : "provider_orphan_teardown",
    status,
    targetType: "provider_orphan",
    targetId: "linode:instance:123",
    requestedBy: "operator",
    input: { engagementId, candidateId: "linode:instance:123" },
    artifactRefs: [],
    events: plan
      ? [{ sequence: 1, level: "info", message: "provider orphan teardown plan recorded", data: {} }]
      : status === "running"
        ? [{ sequence: 1, level: "info", message: "provider orphan teardown requested", data: {} }]
        : [
            { sequence: 1, level: "info", message: "provider orphan teardown requested", data: {} },
            { sequence: 2, level: "info", message: "provider resource delete requested", data: {} }
          ]
  };
}

function providerCatalog() {
  return { provider: "linode", regions: [{ id: "us-sea", label: "us-sea", available: true }], sizes: [{ id: "g6-nanode-1", label: "g6-nanode-1", available: true }], defaults: { region: "us-sea", size: "g6-nanode-1" }, warnings: [] };
}

function readiness() {
  return { target: { name: "barragan-testing", compartmentId: "ocid1.compartment.oc1..testing" }, confirmationToken: "mutate-barragan-testing", expectedInstanceDisplayNames: ["homebase-zy01"], expectedVcnDisplayName: "barragan-zy01", workspace: "/tmp/pilot", guardrails: { noTouchCompartments: [] }, topology: { vcnCidr: "10.0.0.0/16" }, sshIngress: { defaultSourceCidrs: ["192.0.2.1/32"] } };
}

function emptyDashboard() {
  return { generatedAt: "2026-07-08T18:00:00Z", summary: { templates: 0, engagements: 1, activeEngagements: 1, jobRuns: 1, activeInfrastructure: 1, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0 }, inventory: [], orphanCandidates: [], reconciliation: { status: "local-records", detail: "Local records." } };
}
