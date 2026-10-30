/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-dns01";

test("engagement DNS page supports previewed DNS record management", async ({ page }) => {
  await mockApi(page);
  await page.goto("/");

  await expect(page.getByText("ready")).toBeVisible();
  await page.getByRole("button", { name: "DNS" }).click();

  await expect(page.getByRole("heading", { name: "DNS", exact: true })).toBeVisible();
  await expect(page.getByText("they do not create inbound channels", { exact: false })).toBeVisible();
  await expect(page.getByRole("region", { name: "Engagement DNS domains" })).toContainText("example-redteam.test");
  await expect(page.getByRole("region", { name: "DNS edge targets" })).toContainText("198.51.100.42");

  await page.getByRole("button", { name: "Manage DNS" }).click();
  const editor = page.getByRole("region", { name: "DNS records for example-redteam.test" });
  await expect(editor).toBeVisible();
  await expect(editor.getByText("Omitted records are removed by Namecheap.")).toBeVisible();
  await expect(editor.getByText("do not change registrar-level nameservers", { exact: false })).toBeVisible();
  await expect(editor.getByRole("region", { name: "Provider records preserved automatically" })).toContainText("CAA");
  await expect(editor.getByLabel("DNS record type 2").locator("option").filter({ hasText: /^NS$/ })).toHaveCount(1);

  await page.getByLabel("DNS value 1").fill("198.51.100.42");
  await page.getByRole("button", { name: "Add Record" }).click();
  await page.getByLabel("DNS host 4").fill("www");
  await expect(page.getByLabel("DNS edge target 4")).toHaveCount(0);
  const value3 = page.getByLabel("DNS value 4");
  const valueSuggestionsId = await value3.getAttribute("list");
  expect(valueSuggestionsId).toBeTruthy();
  await expect(page.locator(`datalist#${valueSuggestionsId} option[value="198.51.100.42"]`)).toHaveCount(1);
  await value3.fill("198.51.100.42");

  await expect(page.getByLabel("DNS TTL 4")).toHaveValue("600");
  await expect(page.getByLabel("DNS value 4")).toHaveValue("198.51.100.42");

  await page.getByRole("button", { name: "Apply Changes" }).click();
  await expect(page.getByText("DNS preview is ready.")).toBeVisible();
  await expect(page.getByRole("region", { name: "DNS preview diff" })).toContainText("add");
  await expect(page.getByRole("region", { name: "DNS preview diff" })).toContainText("update");

  await expect(await editor.evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBeTruthy();
  await page.screenshot({ path: "test-results/engagement-dns-workflow.png", fullPage: true });

  await page.getByRole("button", { name: "Apply Now" }).click();
  await expect(page.getByRole("region", { name: "DNS job console" })).toContainText("Namecheap DNS setHosts completed");
});

async function mockApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();
    if (!pathname.startsWith("/api/")) {
      await route.continue();
      return;
    }
    if (pathname === "/api/auth/session") {
      await route.fulfill({ json: { authRequired: false, authenticated: false, user: null, mustChangePassword: false } });
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
    if (pathname === "/api/dashboard") {
      await route.fulfill({ json: { dashboard: dashboard() } });
      return;
    }
    if (pathname === "/api/provider-catalog/sketch") {
      await route.fulfill({ json: { catalog: providerCatalog("linode") } });
      return;
    }
    if (pathname === "/api/provider-catalog/sketch/linode") {
      await route.fulfill({ json: { catalog: providerCatalog("linode") } });
      return;
    }
    if (pathname === "/api/provider-catalog/sketch/digitalocean") {
      await route.fulfill({ json: { catalog: providerCatalog("digitalocean") } });
      return;
    }
    if (pathname === `/api/orchestrator/barragan-testing/pilot-standard-rti/readiness`) {
      await route.fulfill({ json: { readiness: readiness() } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/dns` && method === "GET") {
      await route.fulfill({ json: { dns: dnsWorkspace() } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/revisions` && method === "GET") {
      await route.fulfill({ json: { revisions: [] } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/dns/preview` && method === "POST") {
      await route.fulfill({ status: 201, json: { preview: dnsPreview() } });
      return;
    }
    if (pathname === `/api/engagements/${engagementId}/dns/apply` && method === "POST") {
      await route.fulfill({ status: 202, json: { status: "succeeded", job: dnsApplyJob("succeeded") } });
      return;
    }
    if (pathname === "/api/jobs/job-dns-apply") {
      await route.fulfill({ json: { job: dnsApplyJob("succeeded") } });
      return;
    }
    throw new Error(`Unexpected API request in mocked engagement DNS workflow test: ${method} ${pathname}`);
  });
}

function engagementSummary() {
  return {
    id: engagementId,
    name: "DNS01",
    status: "active",
    lifecycle: "active",
    owner: "operator",
    templateId: "standard-rti",
    activeRevision: "rev-dns01-001",
    description: "DNS UI smoke",
    documentationUrl: "",
    jiraUrl: "",
  };
}

function domainSummary() {
  return {
    id: "dom-example",
    domainName: "example-redteam.test",
    registrar: "namecheap",
    registration: {
      createdAt: "2026-01-01",
      expiresAt: "2027-01-01",
      autoRenew: true,
    },
    healthRisk: {
      status: "clear",
      flags: [],
      cooldownUntil: "",
      assignableOverride: false,
    },
    providerStatus: "active",
    notes: "smoke fixture",
    lastSyncedAt: "2026-06-14T03:00:00Z",
    bucket: "currently_being_used",
    engagement: { id: engagementId, name: "DNS01" },
    purpose: "rti, web",
    purposeTags: ["rti", "web"],
  };
}

function dnsWorkspace() {
  const domain = domainSummary();
  return {
    engagementId,
    domains: [
      {
        ...domain,
        dns: {
          domainId: domain.id,
          domainName: domain.domainName,
          provider: "namecheap",
          source: "provider_snapshot",
          syncJobId: "job-sync",
          fetchedAt: "2026-06-14T03:00:00Z",
          readOnly: false,
          currentFingerprint: "sha256:fixture",
          hosts: [
            { name: "@", type: "A", address: "203.0.113.10", ttl: "600", mxPref: "" },
            { name: "@", type: "NS", address: "dns1.registrar-servers.com.", ttl: "1800", mxPref: "" },
            { name: "@", type: "CAA", address: "0 issue \"letsencrypt.org\"", ttl: "1800", mxPref: "" },
            { name: "mail", type: "MX", address: "mail.example-redteam.test.", ttl: "600", mxPref: "10" },
          ],
        },
      },
    ],
    edgeTargets: [
      {
        id: "edge-dns01-us-sea-proxy01-sea-01",
        label: "edge-dns01-us-sea-proxy01-sea-01 (198.51.100.42)",
        chainId: "proxy01-sea-01",
        hostname: "edge-dns01-us-sea-proxy01-sea-01",
        provider: "linode",
        publicIp: "198.51.100.42",
        region: "us-sea",
        proxy: "proxy01",
        status: "ready",
      },
    ],
    supportedRecordTypes: ["A", "AAAA", "CNAME", "TXT", "MX", "NS"],
    defaultTtl: 600,
    notice: "DNS records only change registrar host records; they do not create inbound channels, proxy routes, certificates, or services.",
  };
}

function dnsPreview() {
  return {
    domain: domainSummary(),
    currentRecords: [
      { name: "@", type: "A", address: "203.0.113.10", ttl: "600", mxPref: "" },
      { name: "@", type: "NS", address: "dns1.registrar-servers.com.", ttl: "1800", mxPref: "" },
      { name: "mail", type: "MX", address: "mail.example-redteam.test.", ttl: "600", mxPref: "10" },
      { name: "@", type: "CAA", address: "0 issue \"letsencrypt.org\"", ttl: "1800", mxPref: "" },
    ],
    desiredRecords: [
      { name: "@", type: "A", address: "198.51.100.42", ttl: "600", mxPref: "" },
      { name: "@", type: "NS", address: "dns1.registrar-servers.com.", ttl: "1800", mxPref: "" },
      { name: "mail", type: "MX", address: "mail.example-redteam.test.", ttl: "600", mxPref: "10" },
      { name: "@", type: "CAA", address: "0 issue \"letsencrypt.org\"", ttl: "1800", mxPref: "" },
      { name: "www", type: "A", address: "198.51.100.42", ttl: "600", mxPref: "" },
    ],
    diff: {
      added: [{ name: "www", type: "A", address: "198.51.100.42", ttl: "600", mxPref: "" }],
      updated: [
        {
          before: { name: "@", type: "A", address: "203.0.113.10", ttl: "600", mxPref: "" },
          after: { name: "@", type: "A", address: "198.51.100.42", ttl: "600", mxPref: "" },
        },
      ],
      removed: [],
      unchanged: [
        { name: "@", type: "NS", address: "dns1.registrar-servers.com.", ttl: "1800", mxPref: "" },
        { name: "mail", type: "MX", address: "mail.example-redteam.test.", ttl: "600", mxPref: "10" },
        { name: "@", type: "CAA", address: "0 issue \"letsencrypt.org\"", ttl: "1800", mxPref: "" },
      ],
    },
    currentFingerprint: "sha256:fixture",
  };
}

function dnsApplyJob(status: "running" | "succeeded") {
  return {
    id: "job-dns-apply",
    action: "engagement_dns_apply",
    status,
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: {},
    artifactRefs: [],
    events:
      status === "succeeded"
        ? [
            { sequence: 1, level: "info", message: "engagement DNS apply started", data: { mutation: true } },
            { sequence: 2, level: "info", message: "Namecheap DNS setHosts completed with full desired host list", data: { mutation: true } },
          ]
        : [{ sequence: 1, level: "info", message: "engagement DNS apply started", data: { mutation: true } }],
  };
}

function dashboard() {
  return {
    generatedAt: "2026-06-14T03:00:00Z",
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
    },
    inventory: [],
    orphanCandidates: [],
    reconciliation: {
      status: "mocked",
      detail: "",
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
    cachedAt: "2026-06-14T03:00:00Z",
    expiresAt: "2026-06-14T04:00:00Z",
    warnings: [],
  };
}

function readiness() {
  return {
    target: {
      name: "barragan-testing",
      compartmentId: "ocid1.compartment.oc1..testing",
    },
    confirmationToken: "mutate-barragan-testing",
    expectedInstanceDisplayNames: ["homebase-dns01", "proxy01-dns01", "proxy02-dns01"],
    expectedVcnDisplayName: "barragan-dns01",
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
