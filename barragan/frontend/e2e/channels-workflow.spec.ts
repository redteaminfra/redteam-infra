/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-zy01";

test("Channels page is separated into outbound and inbound operator workflows", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByText("ready")).toBeVisible();
  await page.getByRole("button", { name: "Channels" }).click();

  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toContainText("Standard outbound channels are configured and validated automatically");
  await expect(page.getByRole("region", { name: "Channel configuration" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Record channels" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Outbound channel workflow" })).toHaveCount(0);

  await page.getByRole("button", { name: "Inbound" }).click();
  await expect(page.getByRole("region", { name: "Inbound channel status summary" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Add Inbound Channel" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Inbound channel workflow" })).toHaveCount(0);
});

async function mockApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (!pathname.startsWith("/api/")) {
      await route.continue();
      return;
    }
    if (pathname === "/api/templates") {
      await route.fulfill({ json: { templates: [] } });
      return;
    }
    if (pathname === "/api/engagements") {
      await route.fulfill({ json: { engagements: [engagementSummary()] } });
      return;
    }
    if (pathname === "/api/jobs") {
      await route.fulfill({ json: { jobs: [] } });
      return;
    }
    if (pathname === "/api/provider-catalog/sketch") {
      await route.fulfill({ json: { catalog: providerCatalog("linode") } });
      return;
    }
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness") {
      await route.fulfill({ json: { readiness: readiness() } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/sketch-chains`) {
      await route.fulfill({ json: { sketchChains: [] } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/sketch-ssh-key`) {
      await route.fulfill({ json: { key: null } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      await route.fulfill({ json: { operations: operationsOverview() } });
      return;
    }
    throw new Error(`Unexpected API request in mocked channels concept test: ${pathname}`);
  });
}

function engagementSummary() {
  return {
    id: engagementId,
    name: "ZY01",
    status: "planned",
    owner: "example_operator",
    templateId: "standard-rti",
    activeRevision: "rev-zy01-001",
    description: "",
    documentationUrl: "",
    jiraUrl: "",
  };
}

function readiness() {
  return {
    target: {
      name: "barragan-testing",
      compartmentId: "ocid1.compartment.oc1..testing",
    },
    confirmationToken: "mutate-barragan-testing",
    expectedInstanceDisplayNames: ["homebase-zy01", "proxy01-zy01", "proxy02-zy01"],
    expectedVcnDisplayName: "barragan-zy01",
    workspace: "/tmp/barragan-pilot-standard-rti",
    guardrails: {
      noTouchCompartments: ["RedTeam", "RedTeam-1"],
    },
    topology: {
      vcnCidr: "192.168.0.0/16",
    },
    sshIngress: {
      defaultSourceCidrs: ["160.34.86.0/23"],
    },
  };
}

function providerCatalog(provider: string) {
  return {
    provider,
    regions: [{ id: "us-sea", label: "us-sea", available: true }],
    sizes: [{ id: "g6-nanode-1", label: "g6-nanode-1", available: true }],
    defaults: { region: "us-sea", size: "g6-nanode-1" },
    source: "mock",
    cachedAt: "",
    expiresAt: "",
    warnings: [],
  };
}

function operationsOverview() {
  return {
    engagementId,
    housekeepingItems: "",
    activeJob: null,
    healthSummary: {
      status: "healthy",
      hostCount: 0,
      source: "test",
      lastCheckedAt: null,
      stale: false,
      detail: "",
    },
    coreInfrastructure: [],
    sketchInfrastructure: [],
    outboundChannels: [],
    inboundChannels: [],
    sshConfig: {
      stanza: "",
      downloadName: "zy01-ssh-config",
    },
  };
}
