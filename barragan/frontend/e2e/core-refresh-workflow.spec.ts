/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-zy01";

test("core infrastructure refresh reloads job and operations state", async ({ page }) => {
  const calls = await mockApi(page);

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Barragan", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Infrastructure" }).click();

  const corePanel = page.getByRole("region", { name: "Current core infrastructure" });
  await expect(corePanel).toContainText("Current Core Infrastructure");
  await expect(corePanel).toContainText("job-pilot-001");

  await corePanel.getByRole("button", { name: "Refresh" }).click();

  await expect.poll(() => calls.coreJobRefreshes).toBeGreaterThanOrEqual(2);
  await expect.poll(() => calls.operations).toBeGreaterThanOrEqual(2);
});

test("persisted command activity survives reload and warns only after inactivity", async ({ page }) => {
  const now = Date.now();
  const api = await mockApi(page, new Date(now - 10_000).toISOString());

  await page.goto("/");
  await page.getByRole("button", { name: "Infrastructure" }).click();
  const summary = page.getByRole("region", { name: "Infrastructure deployment console summary" });
  await expect(summary).toContainText("Working — Apply selected RTI capabilities");
  await expect(summary).toContainText("Install baseline RTI tools");
  await summary.getByRole("button", { name: "Open Console" }).click();
  const consolePanel = page.getByRole("region", { name: "Infrastructure deployment console" });
  await expect(consolePanel.locator(".deployment-console-header")).toContainText("Current task:");
  await expect(consolePanel.locator(".deployment-console-footer")).toContainText("Elapsed:");
  await expect(consolePanel.locator(".deployment-console-footer")).toContainText("Last activity:");
  await consolePanel.getByRole("button", { name: "Close" }).click();

  await page.reload();
  await page.getByRole("button", { name: "Infrastructure" }).click();
  await expect(page.getByRole("region", { name: "Infrastructure deployment console summary" })).toContainText(
    "Working — Apply selected RTI capabilities"
  );

  api.observedAt = new Date(Date.now() - 91_000).toISOString();
  await page.reload();
  await page.getByRole("button", { name: "Infrastructure" }).click();
  await expect(page.getByRole("region", { name: "Infrastructure deployment console summary" })).toContainText(
    "Possibly stalled — Apply selected RTI capabilities"
  );
});

async function mockApi(page: Page, observedAt = "") {
  const calls = { coreJobRefreshes: 0, operations: 0, observedAt };

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;

    if (!pathname.startsWith("/api/")) {
      await route.continue();
      return;
    }

    if (pathname === "/api/templates") return route.fulfill({ json: { templates: [] } });
    if (pathname === "/api/engagements") return route.fulfill({ json: { engagements: [engagementSummary()] } });
    if (pathname === "/api/jobs") return route.fulfill({ json: { jobs: [] } });
    if (pathname === "/api/dashboard") return route.fulfill({ json: { dashboard: emptyDashboard() } });
    if (pathname === "/api/health") return route.fulfill({ json: { service: "barragan-api", status: "ok" } });
    if (pathname === "/api/provider-catalog/sketch") return route.fulfill({ json: { catalog: providerCatalog() } });
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness") {
      return route.fulfill({ json: { readiness: readiness() } });
    }
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001") {
      calls.coreJobRefreshes += 1;
      return route.fulfill({ json: { job: pilotJob(calls.observedAt) } });
    }
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      calls.operations += 1;
      return route.fulfill({ json: { operations: operationsOverview(Boolean(calls.observedAt)) } });
    }
    if (pathname === `/api/engagements/${engagementId}/sketch-chains`) {
      return route.fulfill({ json: { sketchChains: [] } });
    }
    if (pathname === `/api/engagements/${engagementId}/sketch-ssh-key`) {
      return route.fulfill({ json: { key: null } });
    }
    if (pathname === `/api/engagements/${engagementId}/workspace`) {
      return route.fulfill({ json: { workspace: null } });
    }
    if (pathname === `/api/engagements/${engagementId}/revisions`) {
      return route.fulfill({ json: { revisions: [] } });
    }

    throw new Error(`Unexpected API request in mocked core refresh test: ${pathname}`);
  });

  return calls;
}

function engagementSummary() {
  return {
    id: engagementId,
    name: "ZY01",
    status: "planned",
    owner: "operator",
    templateId: "standard-rti",
    activeRevision: "rev-1"
  };
}

function readiness() {
  return {
    target: { name: "barragan-testing", compartmentId: "ocid1.compartment.oc1..testing" },
    confirmationToken: "mutate-barragan-testing",
    expectedInstanceDisplayNames: ["homebase-zy01", "proxy01-zy01", "proxy02-zy01"],
    expectedVcnDisplayName: "barragan-zy01",
    workspace: "/tmp/barragan-pilot-standard-rti",
    guardrails: { noTouchCompartments: ["RedTeam", "RedTeam-1"] },
    topology: { vcnCidr: "192.168.0.0/16" },
    sshIngress: { defaultSourceCidrs: ["160.34.86.0/23"] }
  };
}

function providerCatalog() {
  return {
    provider: "linode",
    regions: [{ id: "us-sea", label: "us-sea", available: true }],
    sizes: [{ id: "g6-nanode-1", label: "g6-nanode-1", available: true }],
    defaults: { region: "us-sea", size: "g6-nanode-1" },
    source: "mock",
    cachedAt: "",
    expiresAt: "",
    warnings: []
  };
}

function pilotJob(observedAt = "") {
  if (observedAt) {
    return {
      id: "job-pilot-001",
      action: "pilot_standard_rti_guarded_execute",
      status: "running",
      targetType: "engagement",
      targetId: engagementId,
      requestedBy: "operator",
      input: { engagementId, engagementName: "ZY01" },
      artifactRefs: [],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "infrastructure command started",
          data: {
            eventKind: "command_started",
            step: "ansible_capabilities",
            phase: "Apply selected RTI capabilities",
            startedAt: new Date(Date.now() - 120_000).toISOString(),
            observedAt: new Date(Date.now() - 120_000).toISOString()
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "Ansible task progress",
          data: {
            eventKind: "ansible_task",
            step: "ansible_capabilities",
            phase: "Apply selected RTI capabilities",
            startedAt: new Date(Date.now() - 120_000).toISOString(),
            observedAt,
            task: "Install baseline RTI tools"
          }
        }
      ]
    };
  }
  return {
    id: "job-pilot-001",
    action: "pilot_standard_rti_guarded_execute",
    status: "succeeded",
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId, engagementName: "ZY01" },
    artifactRefs: [],
    events: [
      {
        sequence: 1,
        level: "info",
        message: "pilot deployment ready",
        data: {
          mutationStatus: "deployed",
          ansibleStatus: "configured",
          finalCleanupStatus: "pending_operator_teardown",
          workspace: "/tmp/barragan-pilot-standard-rti"
        }
      }
    ]
  };
}

function operationsOverview(running = false) {
  return {
    engagementId,
    housekeepingItems: "",
    activeJob: {
      id: "job-pilot-001",
      action: "pilot_standard_rti_guarded_execute",
      status: running ? "running" : "succeeded",
      target: "ZY01",
      createdAt: "2026-07-08T18:00:00Z"
    },
    healthSummary: { status: "healthy", hostCount: 0, source: "test", lastCheckedAt: null, stale: false, detail: "" },
    coreInfrastructure: [],
    sketchInfrastructure: [],
    providerFindings: [],
    servicePlacements: [],
    outboundChannels: [],
    inboundChannels: [],
    sshConfig: { stanza: "", downloadName: "zy01-ssh-config" }
  };
}

function emptyDashboard() {
  return {
    generatedAt: "2026-07-08T18:00:00Z",
    summary: {
      templates: 0,
      engagements: 1,
      activeEngagements: 1,
      jobRuns: 0,
      activeInfrastructure: 0,
      attention: 0,
      destroyed: 0,
      lastKnown: 0,
      orphanCandidates: 0,
      recentTeardowns: 0,
      recentArchives: 0
    },
    engagementOverview: {
      active: [],
      recentlyEnded: [],
      recentlyArchived: [],
      windowDays: 30
    },
    systemHealth: {
      api: { status: "ok", detail: "Barragan API is responding.", checkedAt: "2026-07-08T18:00:00Z" },
      database: { status: "ok", detail: "Database query succeeded.", uriScheme: "sqlite", path: "/tmp/barragan.db", seedStatus: "seeded" },
      disk: { status: "ok", detail: "42% disk used at /tmp.", path: "/tmp", freeBytes: 1, totalBytes: 2, usedPercent: 42 },
      providers: { status: "not checked", detail: "Provider connectivity has not been checked.", checkedAt: null }
    },
    inventory: [],
    orphanCandidates: [],
    reconciliation: { status: "provider-reconciled", detail: "" }
  };
}
