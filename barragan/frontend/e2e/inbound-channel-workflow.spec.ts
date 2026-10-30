/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-zy01";

for (const width of [1280, 1600, 1920]) {
  test(`inbound panel and long validation badges fit at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const channel = createdInboundChannel("Validated");
    channel.channelId = "edge-m6v2q8n4-sfo3-01-80-to-homebase-9999-u-m6v2q8n4-invalid";
    await mockApi(page, async ({ pathname }) => {
      if (pathname === `/api/engagements/${engagementId}`) return { engagement: engagementSummary() };
      if (pathname === `/api/engagements/${engagementId}/operations`) return { operations: operationsOverview([channel]) };
      return defaultMock(pathname);
    });
    await page.goto("/");
    await expect(page.locator("header").getByText("ready", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Channels", exact: true }).click();
    await page.getByRole("button", { name: "Inbound", exact: true }).click();
    const panel = page.getByRole("region", { name: "Inbound channel status summary" });
    await expect(panel.getByRole("heading", { name: "Inbound channels" })).toBeVisible();
    const violations = await panel.evaluate((element) => {
      const panelBounds = element.getBoundingClientRect();
      const failures: string[] = [];
      for (const child of element.querySelectorAll("h3, [data-label], .status-pill, button")) {
        const bounds = child.getBoundingClientRect();
        if (bounds.left < panelBounds.left - 1 || bounds.right > panelBounds.right + 1) failures.push(child.textContent || "empty");
      }
      const cell = element.querySelector('[data-label="Status"]')!.getBoundingClientRect();
      for (const badge of element.querySelectorAll('[data-label="Status"] .status-pill')) {
        const bounds = badge.getBoundingClientRect();
        if (bounds.left < cell.left - 1 || bounds.right > cell.right + 1) failures.push("status badge overlaps neighboring column");
      }
      return failures;
    });
    expect(violations).toEqual([]);
    await page.screenshot({ path: `/private/tmp/wi0427-channels-${width}.png` });
  });
}

test("operator adds removes and recovers an inbound channel from the simplified Channels page", async ({ page }) => {
  let operations = operationsOverview([]);
  const calls: Array<{ url: string; method: string; body: unknown }> = [];

  await mockApi(page, async ({ pathname, method, body }) => {
    calls.push({ url: pathname, method, body });
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      return { operations };
    }
    if (pathname === `/api/engagements/${engagementId}/inbound-channels` && method === "POST") {
      operations = operationsOverview([createdInboundChannel("Pending Validation")]);
      return inboundJob("job-inbound-apply", "inbound_channel_apply", "Pending Validation", createdInboundChannel("Pending Validation"));
    }
    if (pathname === `/api/engagements/${engagementId}/inbound-channels/edge-zy01-us-sea-01-80-to-proxy01-18080` && method === "DELETE") {
      operations = operationsOverview([createdInboundChannel("Removed")]);
      return inboundActionJob("job-inbound-remove", "inbound_channel_remove", "Removed");
    }
    if (pathname === `/api/engagements/${engagementId}/inbound-channels/edge-zy01-us-sea-01-80-to-proxy01-18080/recover` && method === "POST") {
      operations = operationsOverview([createdInboundChannel("Pending Validation")]);
      return inboundJob("job-inbound-recover", "inbound_channel_apply", "Pending Validation", createdInboundChannel("Pending Validation"));
    }
    return defaultMock(pathname);
  });

  await page.goto("/");
  await expect(page.locator("header").getByText("ready", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Channels" }).click();

  await expect(page.getByRole("region", { name: "Outbound channel status summary" })).toBeVisible();
  await page.getByRole("button", { name: "Inbound" }).click();
  await expect(page.getByRole("region", { name: "Inbound channel status summary" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Record channels" })).toHaveCount(0);
  await expect(page.getByLabel("inbound apply confirmation")).toHaveCount(0);

  await page.getByRole("button", { name: "Add Inbound Channel" }).click();
  const modal = page.getByRole("region", { name: "Add inbound channel" });
  await expect(modal).toBeVisible();
  await modal.getByLabel("Inbound edge").selectOption(JSON.stringify(["chain-1", "edge-chain-1"]));
  await expect(modal).toContainText("Path: edge-zy01-us-sea-01 -> middle01-zy01 -> proxy01-zy01");
  await expect(modal.getByLabel("Inbound termination")).toContainText("proxy01");
  await expect(modal.getByLabel("Inbound termination")).toContainText("homebase");
  await expect(modal.getByLabel("Inbound termination")).not.toContainText("proxy02");
  await modal.getByLabel("Inbound mode").selectOption("tcp-forward");
  await modal.getByLabel("Inbound external port").fill("80");
  await modal.getByLabel("Inbound termination").selectOption("proxy01-zy01");
  await modal.getByLabel("Inbound internal port").fill("18080");
  await modal.getByLabel("Inbound domain").fill("www.example.invalid");
  await modal.getByLabel("Inbound purpose").fill("Test web route");
  await modal.getByRole("button", { name: "Apply" }).click();

  const createCall = calls.find((call) => call.url === `/api/engagements/${engagementId}/inbound-channels` && call.method === "POST");
  expect(createCall?.body).toEqual({
    chainId: "chain-1",
    edge: "edge-zy01-us-sea-01",
    edgeComponentId: "edge-chain-1",
    protocol: "TCP",
    mode: "tcp-forward",
    externalPort: "80",
    terminatesOn: "proxy01-zy01",
    internalPort: "18080",
    domain: "www.example.invalid",
    purpose: "Test web route",
  });

  await expect(page.getByRole("region", { name: "Channel job console" })).toContainText("job-inbound-apply");
  await page.getByRole("button", { name: "Close" }).click();
  const summary = page.getByRole("region", { name: "Inbound channel status summary" });
  await expect(summary).toContainText("edge-zy01-us-sea-01-80-to-proxy01-18080");
  await expect(summary).toContainText("edge-zy01-us-sea-01:80");
  await expect(summary).toContainText("proxy01-zy01:18080");

  await summary.getByRole("button", { name: "Remove" }).click();
  const removeModal = page.getByRole("region", { name: "Remove inbound channel" });
  await expect(removeModal).toContainText("Remove this inbound channel configuration?");
  await removeModal.getByRole("button", { name: "Confirm" }).click();
  const removeCall = calls.find((call) => call.url.endsWith("/edge-zy01-us-sea-01-80-to-proxy01-18080") && call.method === "DELETE");
  expect(removeCall?.body).toEqual({ confirmation: "remove-inbound-edge-zy01-us-sea-01-80-to-proxy01-18080" });
  await page.getByRole("button", { name: "Close" }).click();
  await expect(summary).toContainText("Removed");

  await summary.getByRole("button", { name: "Restore" }).click();
  const recoverCall = calls.find((call) => call.url.endsWith("/edge-zy01-us-sea-01-80-to-proxy01-18080/recover") && call.method === "POST");
  expect(recoverCall).toBeTruthy();
  await expect(page.getByRole("region", { name: "Channel job console" })).toContainText("job-inbound-recover");
});

test("duplicate edge hostnames preview the exact selected chain component", async ({ page }) => {
  let operations = operationsOverview([]);
  operations.sketchInfrastructure[1].hostname = "edge-shared-zy01";
  operations.sketchInfrastructure[3].hostname = "edge-shared-zy01";
  operations.sketchInfrastructure[3].provider = "digitalocean";
  operations.sketchInfrastructure[3].region = "nyc3";
  operations.sketchInfrastructure[3].publicIp = "198.51.100.50";
  operations.sketchInfrastructure.reverse();
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  await mockApi(page, async ({ pathname, method, body }) => {
    calls.push({ url: pathname, method, body });
    if (pathname === `/api/engagements/${engagementId}/operations`) return { operations };
    if (pathname === `/api/engagements/${engagementId}/inbound-channel-batches/preview` && method === "POST") {
      const request = body as { submissionId: string; channels: Array<Record<string, unknown>> };
      return {
        submissionId: request.submissionId, previewFingerprint: "b".repeat(64),
        channels: request.channels.map((channel) => ({ ...channel, channelId: "channel-exact" })),
        applyOrder: ["channel-exact"], warnings: [], status: "ready",
        summary: "1 inbound channel passed whole-batch preflight."
      };
    }
    if (pathname === `/api/engagements/${engagementId}/inbound-channels/prepare` && method === "POST") {
      const request = body as { channel: Record<string, unknown> };
      const channel = {
        ...request.channel,
        channelId: "channel-exact",
        status: "Pending Apply",
        validation: { status: "Pending Apply", detail: "Saved for review. No infrastructure changes have run." },
      };
      operations = operationsOverview([channel]);
      return { channel, status: "Pending Apply", job: inboundActionJob("job-prepare", "inbound_channel_prepare", "succeeded") };
    }
    return defaultMock(pathname);
  });

  await page.goto("/");
  await expect(page.locator("header").getByText("ready", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Channels" }).click();
  await page.getByRole("button", { name: "Inbound" }).click();
  await page.getByRole("button", { name: "Add Inbound Channel" }).click();
  const modal = page.getByRole("region", { name: "Add inbound channel" });
  const options = modal.getByLabel("Inbound edge").locator("option", { hasText: "edge-shared-zy01" });
  await expect(options).toHaveCount(2);
  const secondValue = await options.filter({ hasText: "proxy02" }).getAttribute("value");
  expect(secondValue).toBe(JSON.stringify(["chain-2", "edge-chain-2"]));
  await modal.getByLabel("Inbound edge").selectOption(secondValue!);
  await expect(modal).toContainText("Path: edge-shared-zy01 -> middle02-zy01 -> proxy02-zy01");
  await expect(modal.getByLabel("Inbound public ingress policy")).toContainText("198.51.100.50");
  await modal.getByLabel("Inbound external port").fill("8443");
  await modal.getByLabel("Inbound backend service").fill("fixture");
  await modal.getByLabel("Inbound internal port").fill("18443");
  await modal.getByRole("button", { name: "Add another" }).click();
  await modal.getByRole("button", { name: "Review 1 channels" }).click();
  await expect(modal.getByLabel("Reviewed inbound batch")).toBeVisible();

  const preview = calls.find((call) => call.url.endsWith("/inbound-channel-batches/preview") && call.method === "POST");
  expect(preview?.body).toMatchObject({
    channels: [{
      chainId: "chain-2", edgeComponentId: "edge-chain-2", edge: "edge-shared-zy01",
      terminatesOn: "proxy02-zy01"
    }]
  });
  await modal.getByRole("button", { name: "Save Pending" }).click();
  await expect(modal).toContainText("Saved Pending. No infrastructure changes have run.");
  const prepare = calls.find((call) => call.url.endsWith("/inbound-channels/prepare") && call.method === "POST");
  expect(prepare?.body).toMatchObject({
    previewFingerprint: "b".repeat(64),
    channel: { chainId: "chain-2", edgeComponentId: "edge-chain-2", edge: "edge-shared-zy01" },
  });
  expect(calls.some((call) => call.url.endsWith("/inbound-channel-batches") && call.method === "POST")).toBe(false);
  const summary = page.getByRole("region", { name: "Inbound channel status summary" });
  await expect(summary).toContainText("channel-exact");
  await expect(summary.getByRole("button", { name: "Preview Apply" })).toBeVisible();
});

test("operator manages certificate assets separately from HTTPS channel bindings", async ({ page }) => {
  const channel = { ...createdInboundChannel("Validated"), protocol: "HTTPS", mode: "https-openresty", externalPort: "443", domain: "secure.example.com" };
  const certificate = {
    id: "cert-secure", name: "Secure wildcard", source: "letsencrypt", targetProxyId: "proxy01-zy01",
    identifiers: ["secure.example.com", "*.example.com"], primaryIdentifier: "secure.example.com", status: "active",
    currentVersionId: "certver-secure", lastJobId: "", versions: [{ id: "certver-secure", sequence: 1, status: "active", acmeEnvironment: "staging", keyGeneration: 1, issuer: "Let's Encrypt", serialNumber: "01", fingerprintSha256: "aa", issuedAt: "2026-06-29T12:00:00Z", expiresAt: "2026-09-27T12:00:00Z", revokedAt: "" }], bindings: [],
    productionConfirmations: { issue: "issue-token", renew: "renew-token", reissue: "reissue-token", revoke: "revoke-token" }
  };
  await mockApi(page, async ({ pathname }) => {
    if (pathname === `/api/engagements/${engagementId}/operations`) return { operations: operationsOverview([channel]) };
    if (pathname === `/api/engagements/${engagementId}/certificates`) return { certificateManager: { engagement: { id: engagementId, name: "ZY01" }, profile: { engagementId, acmeEmail: "operator@example.com", defaultEnvironment: "staging", updatedAt: "" }, certificates: [certificate], proxies: [{ id: "proxy01-zy01", label: "proxy01-zy01", status: "deployed" }], sources: ["letsencrypt", "self-signed", "external"], maxIdentifiers: 100 } };
    if (pathname.endsWith(`/inbound-channels/${channel.channelId}/certificate-binding`)) return { channel, certificate: null, binding: null, candidates: [certificate], routeStatus: "Validated", tlsStatus: "unbound" };
    return defaultMock(pathname);
  });

  await page.goto("/");
  await expect(page.locator("header").getByText("ready", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Certificates" }).click();
  await expect(page.getByRole("heading", { name: "Certificate Manager" })).toBeVisible();
  await expect(page.getByText("Secure wildcard", { exact: true })).toBeVisible();
  await expect(page.getByText("secure.example.com, *.example.com", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Certificate source")).toContainText("Self-Signed");

  await page.getByRole("button", { name: "Channels" }).click();
  await page.getByRole("button", { name: "Inbound" }).click();
  await page.getByRole("button", { name: "Manage Cert" }).click();
  const binding = page.getByRole("region", { name: "SSL/TLS Cert Manager" });
  await expect(binding).toContainText("Certificate binding");
  await expect(binding).toContainText("TLS Unbound");
  await expect(binding.getByLabel("Covering certificate")).toContainText("Secure wildcard");
  await expect(binding.getByRole("button", { name: "Open Certificates" })).toBeVisible();
});

test("operator progressively configures and retains request gates on HTTP and HTTPS routes", async ({ page }) => {
  const httpChannel = {
    ...createdInboundChannel("Validated"),
    channelId: "edge-zy01-us-sea-01-80-to-homebase-9999",
    protocol: "HTTP",
    mode: "http-openresty",
    terminatesOn: "homebase-zy01",
    internalPort: "9999",
    service: "Go Simple Upload Server",
    domain: "upload.example.invalid"
  };
  const httpsChannel = {
    ...httpChannel,
    channelId: "edge-zy01-us-sea-01-443-to-proxy01-8081",
    protocol: "HTTPS",
    mode: "https-openresty",
    externalPort: "443",
    terminatesOn: "proxy01-zy01",
    internalPort: "8081",
    service: "Static Web",
    serviceId: "web-secure",
    serviceType: "web-static",
    domain: "secure.example.invalid"
  };
  const tcpChannel = {
    ...httpChannel,
    channelId: "edge-zy01-us-sea-01-7443-to-homebase-7443",
    protocol: "TCP",
    mode: "tcp-forward",
    externalPort: "7443",
    internalPort: "7443"
  };
  const providedToken = "manual-token-12345";
  const retryToken = "retry-token-789";
  const httpsToken = "https-token-123456";
  type GatePolicy = { configured: boolean; enabled: boolean; headerName: string; token: string; status: string; maxRequestBodyMb: number };
  const policies = new Map<string, GatePolicy>([
    [httpChannel.channelId, { configured: false, enabled: false, headerName: "Authorization", token: "", status: "Not configured", maxRequestBodyMb: 500 }],
    [httpsChannel.channelId, { configured: false, enabled: false, headerName: "Authorization", token: "", status: "Not configured", maxRequestBodyMb: 500 }]
  ]);
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  let returnRunningJob = false;
  const runningJob = {
    id: "job-request-gate-retry",
    action: "inbound_request_header_gate_apply",
    status: "running",
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId, channelId: httpChannel.channelId },
    artifactRefs: [],
    events: [{ sequence: 1, level: "info", message: "request gate convergence started", data: {} }]
  };
  const failedJob = {
    ...runningJob,
    status: "failed",
    events: [...runningJob.events, { sequence: 2, level: "error", message: "request gate convergence failed; retry the saved values", data: {} }]
  };
  const gateWorkspace = (channel: typeof httpChannel, policy: GatePolicy) => {
    const https = channel.mode === "https-openresty";
    const continuation = "\\";
    const curl = !policy.configured || !policy.enabled
      ? ""
      : (https
          ? [
              `curl --include --request GET ${continuation}`,
              `  --resolve '${channel.domain}:443:198.51.100.30' ${continuation}`,
              `  --header '${policy.headerName}: Bearer ${policy.token}' ${continuation}`,
              `  'https://${channel.domain}/'`
            ]
          : [
              `curl --include --request GET ${continuation}`,
              `  --header 'Host: ${channel.domain}' ${continuation}`,
              `  --header '${policy.headerName}: Bearer ${policy.token}' ${continuation}`,
              "  'http://198.51.100.30/'"
            ]).join("\n");
    return { channel, edgePublicIp: "198.51.100.30", gate: policy, authorizedRequest: { method: "GET", curl } };
  };

  await page.addInitScript(() => {
    const copiedValues: string[] = [];
    Object.defineProperty(window, "__copiedRequestGateValues", { configurable: true, value: copiedValues });
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (value: string) => { copiedValues.push(value); } }
    });
  });
  await mockApi(page, async ({ pathname, method, body }) => {
    calls.push({ url: pathname, method, body });
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      return { operations: operationsOverview([httpChannel, httpsChannel, tcpChannel]) };
    }
    if (pathname === `/api/jobs/${runningJob.id}`) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      return { job: failedJob };
    }
    const channel = pathname.includes(httpsChannel.channelId) ? httpsChannel : httpChannel;
    if (pathname.endsWith("/request-header-gate")) {
      const policy = policies.get(channel.channelId)!;
      if (method === "PUT") {
        if (returnRunningJob) {
          returnRunningJob = false;
          return {
            ...gateWorkspace(channel, { ...policy, status: "Applying" }),
            pending: { state: "running", jobId: runningJob.id, message: "Request gate convergence is running." },
            job: runningJob
          };
        }
        const request = body as { enabled: boolean; headerName: string; tokenAction: string; token?: string; maxRequestBodyMb: number };
        const nextPolicy = request.enabled
          ? { configured: true, enabled: true, headerName: request.headerName, token: request.token ?? "", status: "Active", maxRequestBodyMb: request.maxRequestBodyMb }
          : { ...policy, enabled: false, status: "Disabled", maxRequestBodyMb: request.maxRequestBodyMb };
        policies.set(channel.channelId, nextPolicy);
        return gateWorkspace(channel, nextPolicy);
      }
      return gateWorkspace(channel, policy);
    }
    return defaultMock(pathname);
  });

  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/");
  await expect(page.locator("header").getByText("ready", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Channels" }).click();
  await page.getByRole("button", { name: "Inbound" }).click();
  const summary = page.getByRole("region", { name: "Inbound channel status summary" });
  await expect(summary.getByRole("button", { name: "Configure" })).toHaveCount(2);
  expect((await summary.textContent())?.includes(providedToken)).toBe(false);

  await summary.locator(".table-row").filter({ hasText: httpChannel.channelId }).getByRole("button", { name: "Configure" }).click();
  let panel = page.getByRole("region", { name: "Request header access gate" });
  await expect(panel.getByRole("heading", { name: "Configure inbound channel" })).toBeVisible();
  await expect(panel.getByLabel("Enable bearer request gate")).not.toBeChecked();
  await expect(panel.getByLabel("Maximum request body MB")).toHaveValue("500");
  await expect(panel.getByRole("region", { name: "Request size policy" })).toContainText("Default: 500 MB");
  await expect(panel.getByRole("region", { name: "Request access policy" })).toHaveCount(0);
  await expect(panel.getByRole("button", { name: "Save channel policy" })).toBeEnabled();
  await panel.getByLabel("Maximum request body MB").fill("0");
  await expect(panel.getByRole("button", { name: "Save channel policy" })).toBeDisabled();
  await expect(panel.getByText(/whole number from 1 through 10240 MB/)).toBeVisible();
  await panel.getByLabel("Maximum request body MB").fill("625");
  await panel.getByRole("button", { name: "Save channel policy" }).click();
  await expect.poll(() => calls.filter((call) => call.method === "PUT").length).toBe(1);
  expect(calls.find((call) => call.method === "PUT")?.body).toEqual({
    enabled: false,
    headerName: "Authorization",
    tokenAction: "keep",
    maxRequestBodyMb: 625
  });
  await expect(panel.getByRole("region", { name: "Authorized GET example" })).toHaveCount(0);
  let bounds = await panel.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.y).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(1280);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(720);
  await panel.getByLabel("Enable bearer request gate").check();
  await expect(panel.getByRole("region", { name: "Request access policy" })).toBeVisible();
  await expect(panel.getByLabel("Request gate bearer token")).toHaveValue("");
  const tokenInput = panel.getByLabel("Request gate bearer token");
  await expect(tokenInput).toHaveAttribute("maxlength", "20");
  await tokenInput.fill("S".repeat(7));
  await expect(panel.getByRole("button", { name: "Save channel policy" })).toBeDisabled();
  await tokenInput.fill("P".repeat(21));
  expect(await tokenInput.evaluate((element) => ({ length: (element as HTMLInputElement).value.length, maxLength: (element as HTMLInputElement).maxLength }))).toEqual({ length: 20, maxLength: 20 });
  await panel.getByLabel("Request gate header name").fill("1-Bad-Header");
  await expect(panel.getByText(/beginning with a letter/)).toBeVisible();
  await expect(panel.getByRole("button", { name: "Save channel policy" })).toBeDisabled();
  await panel.getByLabel("Request gate header name").fill("X-RTI-Access");
  await panel.getByLabel("Request gate bearer token").fill(providedToken);
  const firstPreviewCurl = gateWorkspace(httpChannel, {
    configured: true,
    enabled: true,
    headerName: "X-RTI-Access",
    token: providedToken,
    status: "Active",
    maxRequestBodyMb: 625
  }).authorizedRequest.curl;
  await expect(panel.getByRole("region", { name: "Authorized GET example" }).locator("pre")).toHaveText(firstPreviewCurl);
  bounds = await panel.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(1280);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(720);
  await panel.getByRole("button", { name: "Copy", exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as Window & { __copiedRequestGateValues: string[] }).__copiedRequestGateValues.at(-1))).toBe(providedToken);
  await panel.getByRole("button", { name: "Copy curl" }).click();
  await expect.poll(() => page.evaluate(() => (window as Window & { __copiedRequestGateValues: string[] }).__copiedRequestGateValues.at(-1))).toBe(firstPreviewCurl);
  await panel.getByRole("button", { name: "Save channel policy" }).click();
  await expect.poll(() => calls.filter((call) => call.method === "PUT").length).toBe(2);
  expect(calls.filter((call) => call.method === "PUT")[1].body).toEqual({
    enabled: true,
    headerName: "X-RTI-Access",
    tokenAction: "provide",
    token: providedToken,
    maxRequestBodyMb: 625
  });
  await panel.getByRole("button", { name: "Close" }).click();
  await summary.locator(".table-row").filter({ hasText: httpChannel.channelId }).getByRole("button", { name: "Configure" }).click();
  panel = page.getByRole("region", { name: "Request header access gate" });
  await expect(panel.getByLabel("Enable bearer request gate")).toBeChecked();
  const activeCurlText = await panel.getByRole("region", { name: "Authorized GET example" }).locator("pre").textContent();
  expect(activeCurlText === firstPreviewCurl).toBe(true);
  await panel.getByRole("button", { name: "Copy curl" }).click();
  const copiedActiveCurl = await page.evaluate(() => (window as Window & { __copiedRequestGateValues: string[] }).__copiedRequestGateValues.at(-1) ?? "");
  expect(copiedActiveCurl === activeCurlText).toBe(true);
  const putCountBeforeGenerate = calls.filter((call) => call.method === "PUT").length;
  await panel.getByRole("button", { name: "Generate" }).click();
  const generatedToken = await panel.getByLabel("Request gate bearer token").inputValue();
  expect({ length: generatedToken.length, urlSafe: /^[A-Za-z0-9_-]+$/.test(generatedToken) }).toEqual({ length: 20, urlSafe: true });
  expect(generatedToken === providedToken).toBe(false);
  expect(calls.filter((call) => call.method === "PUT")).toHaveLength(putCountBeforeGenerate);
  await panel.getByRole("button", { name: "Save channel policy" }).click();
  await expect.poll(() => calls.filter((call) => call.method === "PUT").length).toBe(3);
  expect(calls.filter((call) => call.method === "PUT")[2].body).toEqual({ enabled: true, headerName: "X-RTI-Access", tokenAction: "provide", token: generatedToken, maxRequestBodyMb: 625 });
  await panel.getByLabel("Enable bearer request gate").uncheck();
  await expect(panel.getByRole("region", { name: "Request access policy" })).toHaveCount(0);
  await panel.getByRole("button", { name: "Save channel policy" }).click();
  await expect.poll(() => calls.filter((call) => call.method === "PUT").length).toBe(4);
  expect(calls.filter((call) => call.method === "PUT")[3].body).toEqual({
    enabled: false,
    headerName: "X-RTI-Access",
    tokenAction: "keep",
    maxRequestBodyMb: 625
  });
  await panel.getByRole("button", { name: "Close" }).click();

  await summary.locator(".table-row").filter({ hasText: httpChannel.channelId }).getByRole("button", { name: "Configure" }).click();
  panel = page.getByRole("region", { name: "Request header access gate" });
  await expect(panel.getByLabel("Enable bearer request gate")).not.toBeChecked();
  await expect(panel.getByLabel("Request gate bearer token")).toHaveCount(0);
  await panel.getByLabel("Enable bearer request gate").check();
  await expect(panel.getByLabel("Request gate bearer token")).toHaveValue(generatedToken);

  await panel.getByLabel("Request gate bearer token").fill(retryToken);
  returnRunningJob = true;
  await panel.getByRole("button", { name: "Save channel policy" }).click();
  await expect(panel.getByRole("button", { name: "Saving channel policy…" })).toBeDisabled();
  await expect(panel.getByRole("button", { name: "Retry channel policy" })).toBeEnabled();
  await expect(panel.getByRole("status")).toContainText("failed");
  await expect(panel.getByLabel("Request gate bearer token")).toHaveValue(retryToken);
  await panel.getByRole("button", { name: "Retry channel policy" }).click();
  await expect.poll(() => calls.filter((call) => call.method === "PUT").length).toBe(6);
  expect(calls.filter((call) => call.method === "PUT")[5].body).toEqual({
    enabled: true,
    headerName: "X-RTI-Access",
    tokenAction: "provide",
    token: retryToken,
    maxRequestBodyMb: 625
  });
  await panel.getByRole("button", { name: "Close" }).click();

  await page.setViewportSize({ width: 1600, height: 900 });
  await summary.locator(".table-row").filter({ hasText: httpsChannel.channelId }).getByRole("button", { name: "Configure" }).click();
  panel = page.getByRole("region", { name: "Request header access gate" });
  await expect(panel.getByLabel("Enable bearer request gate")).not.toBeChecked();
  await expect(panel.getByRole("region", { name: "Authorized GET example" })).toHaveCount(0);
  await panel.getByLabel("Enable bearer request gate").check();
  await panel.getByLabel("Request gate bearer token").fill(httpsToken);
  const httpsCurl = [
    "curl --include --request GET \\",
    "  --resolve 'secure.example.invalid:443:198.51.100.30' \\",
    `  --header 'Authorization: Bearer ${httpsToken}' \\`,
    "  'https://secure.example.invalid/'"
  ].join("\n");
  await expect(panel.getByRole("region", { name: "Authorized GET example" }).locator("pre")).toHaveText(httpsCurl);
  bounds = await panel.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(1600);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(900);
  expect(calls.filter((call) => call.url.endsWith("/request-header-gate") && call.method === "GET").length).toBeGreaterThanOrEqual(5);
});

test("operator saves and applies a selected optional role to running core hosts", async ({ page }) => {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  let selectedOptionals: Array<{ hostClass: string; id: string }> = [];
  const succeededJob = {
    id: "job-optional-role-apply",
    action: "capability_reconciliation_apply",
    status: "succeeded",
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId },
    artifactRefs: [],
    events: [
      { sequence: 1, level: "info", message: "optional capability Ansible workspace rendered", data: {} },
      { sequence: 2, level: "info", message: "optional capability Ansible apply succeeded", data: {} }
    ]
  };

  await mockApi(page, async ({ pathname, method, body }) => {
    calls.push({ url: pathname, method, body });
    if (pathname === `/api/engagements/${engagementId}/operations`) return { operations: operationsOverview([]) };
    if (pathname === `/api/engagements/${engagementId}/capabilities` && method === "PATCH") {
      selectedOptionals = ((body as { selectedOptionals?: Array<{ hostClass: string; id: string }> })?.selectedOptionals ?? []);
      return { capabilities: optionalRoleCapabilities(selectedOptionals) };
    }
    if (pathname === `/api/engagements/${engagementId}/capabilities`) return { capabilities: optionalRoleCapabilities(selectedOptionals) };
    if (pathname === `/api/engagements/${engagementId}/workspace/capability-lock`) {
      return { render: { capabilityLock: { relativePath: "barragan/capability-lock.yml", path: "/retained/zy01/barragan/capability-lock.yml", status: "passed" } } };
    }
    if (pathname === `/api/engagements/${engagementId}/capabilities/reconciliation` && method === "POST") {
      return { reconciliation: { status: "succeeded", plan: reconciliationPlan([{ id: "go-simple-upload-server", role: "go_simple_upload_server" }]), job: succeededJob } };
    }
    if (pathname === `/api/engagements/${engagementId}/capabilities/reconciliation`) {
      return { reconciliation: { status: selectedOptionals.length ? "ready" : "no_selection", plan: reconciliationPlan(selectedOptionals.length ? [{ id: "go-simple-upload-server", role: "go_simple_upload_server" }] : []), job: null } };
    }
    if (pathname === `/api/engagements/${engagementId}/capabilities/desktop`) return { service: {}, apps: [] };
    return defaultMock(pathname);
  });

  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/");
  await expect(page.locator("header").getByText("ready", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Capabilities" }).click();
  const capabilityWorkspace = page.getByRole("region", { name: "Capabilities" });
  const applyButton = capabilityWorkspace.getByRole("button", { name: "Save & apply selected optional roles" });
  await expect(applyButton).toBeDisabled();
  await capabilityWorkspace.getByLabel("Enable Go Simple Upload Server").check();
  await expect(applyButton).toBeEnabled();
  await applyButton.click();

  await expect.poll(() => calls.filter((call) => call.url.endsWith("/capabilities/reconciliation") && call.method === "POST").length).toBe(1);
  expect(selectedOptionals).toEqual([{ hostClass: "homebase", id: "go-simple-upload-server" }]);
  const consolePanel = page.getByRole("region", { name: "Optional role reconciliation console" });
  await expect(consolePanel).toContainText("Selected optional roles were applied successfully");
  await expect(consolePanel).toContainText("Optional-role Ansible apply succeeded");
  const bounds = await consolePanel.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(1280);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(720);
  expect(calls.some((call) => call.url.includes("terraform"))).toBe(false);
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
  if (pathname === "/api/auth/session") {
    return { authRequired: false, authenticated: true, user: null, mustChangePassword: false };
  }
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
        generatedAt: "2026-06-29T12:00:00Z",
        summary: { templates: 0, engagements: 1, activeEngagements: 1, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0 },
        reconciliation: { status: "ready", detail: "Mock inventory is current.", lastCheckedAt: "2026-06-29T12:00:00Z" },
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
  if (pathname === `/api/engagements/${engagementId}/revisions`) {
    return { revisions: [] };
  }
  if (pathname === `/api/engagements/${engagementId}/inbound-channel-batches/latest`) {
    return { job: null };
  }
  throw new Error(`Unexpected API request in mocked inbound workflow test: ${pathname}`);
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

function optionalRoleCapabilities(selectedOptionals: Array<{ hostClass: string; id: string }>) {
  const selected = selectedOptionals.some((row) => row.hostClass === "homebase" && row.id === "go-simple-upload-server");
  return {
    workspace: { engagementId, slug: "zy01", path: "/retained/zy01", status: "capabilities-configured", profileId: "standard-rti", metadata: {} },
    profileResolution: {
      source: { path: "/opt/redteam-infra", kind: "git", warning: "" },
      profile: { id: "standard-rti", name: "Standard RTI", description: "Default RTI profile." },
      status: "passed",
      hostClasses: {
        homebase: {
          essential: [],
          default: [],
          optional: [{
            id: "go-simple-upload-server",
            name: "Go Simple Upload Server",
            description: "Run the stock upload server role on Homebase.",
            hostClass: "homebase",
            classification: "optional",
            resolution: "catalog",
            executable: true,
            selected,
            locked: false,
            implementation: { type: "role", path: "ansible/roles/go_simple_upload_server", role: "go_simple_upload_server" },
            operator: { visible: true, selectable: true }
          }],
          internal: [],
          unsupported: []
        }
      },
      summary: { total: 1, catalog: 1, selected: selected ? 1 : 0 },
      warnings: [],
      selection: { selectedDefaults: [], deselectedDefaults: [], selectedOptionals, excludedCapabilities: [] }
    },
    overrides: { selectedDefaults: [], deselectedDefaults: [], selectedOptionals, excludedCapabilities: [] },
    executionPolicy: { terraform: false, ansible: true, providerMutation: false, reason: "Optional role reconciliation uses Ansible only." }
  };
}

function reconciliationPlan(homebaseRoles: Array<{ id: string; role: string }>) {
  return {
    selectedCount: homebaseRoles.length,
    executableCount: homebaseRoles.length,
    roleCount: homebaseRoles.length,
    rolesByHostClass: { common: [], homebase: homebaseRoles, proxy: [], elk: [] },
    targetHostClasses: homebaseRoles.length ? ["homebase"] : [],
    availableHostClasses: ["homebase", "proxy"],
    skipped: [],
    warnings: [],
    errors: []
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

function operationsOverview(inboundChannels: Array<Record<string, unknown>>) {
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
    coreInfrastructure: [
      coreHost("homebase-zy01", "homebase"),
      coreHost("proxy01-zy01", "proxy"),
      coreHost("proxy02-zy01", "proxy"),
    ],
    sketchInfrastructure: [
      sketchHost("chain-1", "middle01-zy01", "middle", "proxy01"),
      sketchHost("chain-1", "edge-zy01-us-sea-01", "edge", "proxy01"),
      sketchHost("chain-2", "middle02-zy01", "middle", "proxy02"),
      sketchHost("chain-2", "edge-zy01-us-ash-02", "edge", "proxy02"),
    ],
    outboundChannels: [],
    inboundChannels,
    sshConfig: {
      stanza: "",
      downloadName: "zy01-ssh-config",
    },
  };
}

function coreHost(hostname: string, role: string) {
  const semanticId = /^(homebase|proxy[0-9]+)-/.exec(hostname)?.[1] ?? "";
  return {
    hostname,
    ...(semanticId ? { hostId: semanticId, logicalName: semanticId, expectedHostname: hostname } : {}),
    role,
    publicIp: "203.0.113.10",
    privateIp: "192.168.0.10",
    region: "us-sanjose-1",
    compartment: "barragan-testing",
    services: ["SSH"],
    health: { status: "healthy", source: "test", lastCheckedAt: "", stale: false, detail: "" },
  };
}

function sketchHost(chainId: string, hostname: string, role: string, proxy: string) {
  return {
    chainId,
    componentId: `${role}-${chainId}`,
    hostname,
    provider: "linode",
    role,
    publicIp: role === "edge" ? "198.51.100.30" : "198.51.100.20",
    region: "us-sea",
    proxy,
    assignedProxyId: proxy,
    status: "deployed",
    burned: false,
    burnedNote: "",
  };
}

function createdInboundChannel(status: string) {
  return {
    channelId: "edge-zy01-us-sea-01-80-to-proxy01-18080",
    chainId: "chain-1",
    edgeComponentId: "edge-chain-1",
    middleComponentId: "middle-chain-1",
    domain: "www.example.invalid",
    protocol: "TCP",
    mode: "tcp-forward",
    externalPort: "80",
    edge: "edge-zy01-us-sea-01",
    middle: "middle01-zy01",
    proxy: "proxy01-zy01",
    terminatesOn: "proxy01-zy01",
    service: "Inbound service",
    internalPort: "18080",
    purpose: "Test web route",
    status,
    validation: {
      status,
      externalIngressVerified: false,
      checkedAt: status === "Removed" ? "2026-06-04T16:00:00+00:00" : "",
      detail: status,
    },
  };
}

function inboundJob(id: string, action: string, status: string, channel: Record<string, unknown>) {
  return {
    channel,
    ...inboundActionJob(id, action, status),
  };
}

function inboundActionJob(id: string, action: string, status: string) {
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
