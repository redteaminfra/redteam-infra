/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-zy01";

test("outbound channels are summarized and auto-configured from deployment output", async ({ page }) => {
  let operations = operationsOverview("Pending Core Apply");
  const calls: Array<{ url: string; method: string; body: unknown }> = [];

  await mockApi(page, async ({ pathname, method, body }) => {
    calls.push({ url: pathname, method, body });
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      return { operations };
    }
    if (pathname === `/api/engagements/${engagementId}/outbound-channels/chain-1/apply`) {
      operations = operationsOverview("Pending Validation");
      return outboundJob("job-outbound-apply", "outbound_channel_apply", "Pending Validation");
    }
    if (pathname === `/api/engagements/${engagementId}/outbound-channels/chain-1/validate`) {
      operations = operationsOverview("Validated");
      return outboundJob("job-outbound-validate", "outbound_channel_validation", "Validated");
    }
    return defaultMock(pathname);
  });

  await page.goto("/");
  await expect(page.locator("header").getByText("ready")).toBeVisible();
  await page.getByRole("button", { name: "Channels" }).click();

  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toContainText("proxy01-egress");
  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toContainText("proxy01-zy01");
  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toContainText("edge-zy01-us-sea-01");
  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toContainText("3333");
  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toContainText("Ready");

  await expect(page.getByRole("button", { name: "Preview Apply Plan" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Apply Core Channel Config" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Validate From Homebase" })).toHaveCount(0);

  const applyCall = calls.find((call) => call.url === `/api/engagements/${engagementId}/outbound-channels/chain-1/apply`);
  expect(applyCall?.method).toBe("POST");
  expect(applyCall?.body).toEqual({ confirmation: "apply-outbound-chain-1" });
  const validateCall = calls.find((call) => call.url === `/api/engagements/${engagementId}/outbound-channels/chain-1/validate`);
  expect(validateCall?.method).toBe("POST");
  expect(validateCall?.body).toEqual({ confirmation: "validate-outbound-chain-1" });
});

async function mockApi(
  page: Page,
  handler: (request: { pathname: string; method: string; body: unknown }) => Record<string, unknown> | Promise<Record<string, unknown>>
) {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (!pathname.startsWith("/api/")) {
      await route.continue();
      return;
    }
    let body: unknown = null;
    try {
      body = request.postDataJSON();
    } catch {
      body = null;
    }
    await route.fulfill({ json: await handler({ pathname, method: request.method(), body }) });
  });
}

function defaultMock(pathname: string) {
  if (pathname === "/api/templates") {
    return { templates: [] };
  }
  if (pathname === "/api/engagements") {
    return { engagements: [engagementSummary()] };
  }
  if (pathname === "/api/jobs") {
    return { jobs: [] };
  }
  if (pathname === "/api/dashboard") {
    return {
      dashboard: {
        generatedAt: "2026-06-26T20:00:00Z",
        summary: {
          templates: 0,
          engagements: 1,
          activeEngagements: 1,
          jobRuns: 0,
          activeInfrastructure: 0,
          attention: 0,
          destroyed: 0,
          lastKnown: 0,
          orphanCandidates: 0
        },
        reconciliation: {
          status: "ready",
          detail: "Mock inventory is current.",
          lastCheckedAt: "2026-06-26T20:00:00Z"
        },
        systemHealth: {
          api: { status: "healthy", detail: "Mock API is available." },
          database: { status: "healthy", detail: "Mock database is available." },
          providers: { status: "healthy", detail: "Mock providers are available." },
          disk: { status: "healthy", detail: "Mock disk is available." }
        },
        orphanCandidates: []
      }
    };
  }
  if (pathname === "/api/provider-catalog/sketch") {
    return { catalog: providerCatalog("linode") };
  }
  if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness") {
    return { readiness: readiness() };
  }
  if (pathname === `/api/engagements/${engagementId}/sketch-chains`) {
    return { sketchChains: [] };
  }
  if (pathname === `/api/engagements/${engagementId}/sketch-ssh-key`) {
    return { key: null };
  }
  throw new Error(`Unexpected API request in mocked outbound workflow test: ${pathname}`);
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

function operationsOverview(status: "Pending Core Apply" | "Pending Validation" | "Validated") {
  return {
    engagementId,
    housekeepingItems: "",
    activeJob: null,
    healthSummary: {
      status: "healthy",
      hostCount: 5,
      source: "test",
      lastCheckedAt: null,
      stale: false,
      detail: "",
    },
    coreInfrastructure: [],
    sketchInfrastructure: [],
    outboundChannels: [
      {
        chainId: "chain-1",
        proxy: "proxy01-zy01",
        middle: "middle01-zy01",
        edge: "edge-zy01-us-sea-01",
        port: "3333",
        region: "us-sea",
        provider: "linode",
        domain: "proxy01-egress",
        purpose: "operator route",
        status,
        profileName: "proxy01-egress",
        publicationPath: "/opt/proxy01/proxychains.conf",
        validation: {
          origin: "homebase",
          shellDisplay: "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
          expectedPublicIp: "203.0.113.30",
          status,
          checkedAt: status === "Validated" ? "2026-06-04T16:00:00+00:00" : "",
          detail: status === "Validated" ? "Observed 203.0.113.30." : "Pending.",
        },
      },
    ],
    inboundChannels: [],
    sshConfig: {
      stanza: "",
      downloadName: "zy01-ssh-config",
    },
  };
}

function outboundJob(id: string, action: string, status: string) {
  return {
    job: {
      id,
      action,
      status: "succeeded",
      targetType: "engagement",
      targetId: engagementId,
      requestedBy: "operator",
      input: { engagementId },
      artifactRefs: [],
      events: [
        {
          sequence: 1,
          level: "info",
          message: `${action} ${status}`,
          data: { status },
        },
      ],
    },
    status,
  };
}
