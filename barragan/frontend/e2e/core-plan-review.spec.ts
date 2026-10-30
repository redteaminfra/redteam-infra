/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, type Page, test } from "@playwright/test";

const engagementId = "eng-wi0266-e2e";
const confirmationToken = "mutate-barragan-testing";

test("reviews and applies only the exact deployable core plan", async ({ page }) => {
  const api = await mockCorePlanApi(page);

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Barragan", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Infrastructure" }).click();

  await expect(page.getByRole("heading", { name: "2. Review Infrastructure Plan" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Infrastructure lifecycle" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Tear Down Infrastructure" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Teardown progress" })).toHaveCount(0);
  await expect.poll(() => api.staleLifecycleReads).toBeGreaterThan(0);

  const prepare = page.getByRole("button", { name: "Prepare Infrastructure Plan" });
  await prepare.focus();
  await page.keyboard.press("Enter");

  const review = page.getByRole("region", { name: "Infrastructure plan review" });
  const planStatus = review.getByRole("status");
  await expect(planStatus).toHaveAttribute("aria-live", "polite");
  await expect(planStatus).toHaveText("preparing");
  await expect(page.getByRole("button", { name: "Preparing Infrastructure Plan" })).toBeDisabled();
  await expect.poll(() => api.planReadsById["plan-destructive"] ?? 0).toBeGreaterThan(0);
  await expect(planStatus).toHaveText("ready");
  await expect(page.getByRole("heading", { name: "3. Deploy Infrastructure" })).toBeFocused();
  await expect(page.getByRole("listitem").filter({ hasText: "Step 3" }).getByText("PENDING", { exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toContainText("Deployment blocked");
  await expect(page.getByRole("button", { name: "Deploy" })).toBeDisabled();

  await prepare.press("Enter");
  await expect(planStatus).toHaveText("preparing");
  await expect.poll(() => api.planReadsById["plan-no-changes"] ?? 0).toBeGreaterThan(0);
  await expect(planStatus).toHaveText("no_changes");
  await expect(page.getByText("No core changes.")).toBeVisible();
  await expect(page.getByLabel("Guided deployment confirmation")).toHaveCount(0);

  await prepare.press("Enter");
  await expect(planStatus).toHaveText("preparing");
  await expect.poll(() => api.planReadsById["plan-output-only"] ?? 0).toBeGreaterThan(0);
  await expect(planStatus).toHaveText("ready");
  await expect(page.getByLabel("Terraform action counts")).toContainText("Output1");
  await expect(page.getByLabel("Outputs resource changes")).toContainText("OutputHomebase public IP");
  const computeProfile = page.getByRole("region", { name: "Resolved compute profile" });
  await expect(computeProfile).toContainText("Standard RTI");
  await expect(computeProfile.getByRole("article", { name: "Homebase compute sizing" })).toContainText("BM.Standard3.64");
  await expect(computeProfile.getByRole("article", { name: "Homebase compute sizing" })).toContainText("1,024 GB");
  await expect(computeProfile.getByRole("article", { name: "Proxy compute sizing" })).toContainText("2 nodes");
  await expect(computeProfile.getByRole("article", { name: "ELK compute sizing" })).toContainText("0 nodes");
  await expect(computeProfile.getByText("512 GiB")).toHaveCount(3);
  await expect(computeProfile.locator("input, select, textarea")).toHaveCount(0);
  await expect(page.getByText("No core changes.")).toHaveCount(0);
  await expect(page.getByLabel("Guided deployment confirmation")).toBeVisible();
  await expect(page.getByRole("listitem").filter({ hasText: "Step 3" }).getByText("PENDING", { exact: true })).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(review).toBeVisible();
  await expect(page.getByLabel("Validated post-core rollout")).toBeVisible();
  await expect(page.getByLabel("Terraform action counts")).toBeVisible();
  expect(await review.evaluate((element) => element.getBoundingClientRect().right <= window.innerWidth + 1)).toBe(true);
  expect(await page.getByLabel("Terraform action counts").evaluate(
    (element) => element.getBoundingClientRect().right <= window.innerWidth + 1
  )).toBe(true);
  expect(await computeProfile.evaluate((element) => element.getBoundingClientRect().right <= window.innerWidth + 1)).toBe(true);
  const profileCards = computeProfile.getByRole("article");
  for (let index = 0; index < await profileCards.count(); index += 1) {
    expect(await profileCards.nth(index).evaluate((element) => element.getBoundingClientRect().right <= window.innerWidth + 1)).toBe(true);
  }

  await page.getByLabel("Confirmation token").fill(confirmationToken);
  await page.getByRole("button", { name: "Deploy" }).click();
  await expect.poll(() => api.applyBodies.length).toBe(1);
  expect(api.applyPaths).toEqual([`/api/engagements/${engagementId}/deployment-plans/plan-output-only/apply`]);
  expect(api.applyBodies).toEqual([{ confirmMutation: confirmationToken }]);

  await expect(page.getByRole("region", { name: "Manage running infrastructure" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Infrastructure lifecycle" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Tear Down Infrastructure" })).toBeVisible();

  // Every request is intercepted. The only mutation after plan preparation is the
  // mocked exact-plan apply, so this disposable fixture creates nothing to clean up.
  expect(api.unexpectedMutations).toEqual([]);
  expect(api.createdRecordIds).toEqual([]);
  expect(api.cloudMutationRequests).toEqual([]);
});

test("shows the bounded Sketch scope without offering an unfinished deployment", async ({ page }) => {
  const api = await mockCorePlanApi(page, true);
  await page.goto("/");
  await page.getByRole("button", { name: "Infrastructure" }).click();
  await page.getByRole("button", { name: "Prepare Infrastructure Plan" }).click();

  const scope = page.getByLabel("Reviewed Sketch authorization");
  await expect(scope).toContainText("DigitalOcean image ubuntu-24-04-x64");
  await expect(scope).toContainText("managed connection connection-do");
  await expect(scope).toContainText("Public TCP 80, 443, 2222; no public UDP or IPv6");
  await expect(scope).toContainText("Peer ingress from the created Sketch nodes permits TCP, UDP, and ICMP; outbound IPv4 is unrestricted");
  await expect(page.getByLabel("Validated post-core rollout")).toContainText("s-1vcpu-1gb");
  // This bounded fixture lacks current keyed authorization, so the plan is
  // invalidated rather than offering a confirmation for an unfinished rollout.
  await expect(page.getByRole("region", { name: "Infrastructure plan review" }).getByRole("status")).toHaveText("invalidated");
  await expect(page.getByLabel("Confirmation token")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Deploy", exact: true })).toHaveCount(0);
  expect(api.applyPaths).toEqual([]);
});

test("scope review keeps complete values in readable rows at operator viewport widths", async ({ page }) => {
  const api = await mockCorePlanApi(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Infrastructure", exact: true }).click();
  await page.getByRole("button", { name: "Prepare Infrastructure Plan" }).click();
  const review = page.getByRole("region", { name: "Infrastructure plan review" });
  await expect(review.getByRole("status")).toHaveText("ready");
  const scope = review.locator(".deployment-checkout-review");
  for (const width of [760, 1280, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1080 });
    await scope.scrollIntoViewIfNeeded();
    const layout = await scope.evaluate((element) => {
      const rows = Array.from(element.children).map((row) => {
        const bounds = row.getBoundingClientRect();
        return { left: bounds.left, right: bounds.right, top: bounds.top, bottom: bounds.bottom,
          fits: row.scrollWidth <= row.clientWidth + 1,
          valuesFit: Array.from(row.querySelectorAll("strong")).every((value) => value.scrollWidth <= value.clientWidth + 1)
        };
      });
      const main = document.querySelector("main")!;
      return { rows, pageFits: document.documentElement.scrollWidth <= innerWidth + 1,
        mainFits: main.scrollWidth <= main.clientWidth + 1 };
    });
    expect(layout.pageFits, `page fits at ${width}`).toBe(true);
    expect(layout.mainFits, `main fits at ${width}`).toBe(true);
    for (let index = 0; index < layout.rows.length; index += 1) {
      const row = layout.rows[index];
      expect(row.fits && row.valuesFit, `scope row ${index} at ${width}`).toBe(true);
      if (index) expect(row.top).toBeGreaterThanOrEqual(layout.rows[index - 1].bottom - 1);
    }
    await expect(scope).toContainText("Core Terraform plan → core configuration and capabilities → validated sketch rollout");
    await expect(scope).toContainText("160.34.86.0/23");
    await page.screenshot({ path: test.info().outputPath(`scope-${width}.png`) });
  }
  expect(api.applyPaths).toEqual([]);
  expect(api.unexpectedMutations).toEqual([]);
});

for (const chainCount of [1, 3]) {
  test(`${chainCount}-chain editor keeps full selections and keyboard order across desktop widths`, async ({ page }) => {
    const api = await mockCorePlanApi(page, false, chainCount);
    await page.goto("/");
    await page.getByRole("button", { name: "Infrastructure", exact: true }).click();
    const cards = page.locator(".sketch-chain-card:not(.locked)");
    await expect(cards).toHaveCount(chainCount);
    await expect(cards.first().getByLabel("proxy01-chain-1 middle region", { exact: true })).toHaveValue("us-sea");
    const advanced = cards.locator("details");
    for (const detail of await advanced.all()) await expect(detail).not.toHaveAttribute("open", "");

    for (const width of [1280, 1440, 1600, 1920]) {
      await page.setViewportSize({ width, height: width === 1280 ? 720 : width === 1920 ? 1080 : 900 });
      // Include advanced sizing in the readable-value check, then restore the
      // default collapsed view for the operator screenshot.
      for (const detail of await advanced.all()) await detail.locator("summary").click();
      const layout = await cards.evaluateAll((elements) => {
        const main = document.querySelector("main")!;
        const context = document.createElement("canvas").getContext("2d")!;
        const clipped = elements.flatMap((card) => Array.from(card.querySelectorAll("select")).map((select) => {
          const style = getComputedStyle(select);
          context.font = style.font;
          const selected = select.selectedOptions[0]?.textContent ?? "";
          const available = select.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight) - 22;
          return { label: select.getAttribute("aria-label"), selected, fits: context.measureText(selected).width <= available };
        })).filter((control) => !control.fits);
        return { pageFits: document.documentElement.scrollWidth <= innerWidth + 1,
          mainFits: main.scrollWidth <= main.clientWidth + 1,
          cardsFit: elements.every((card) => card.scrollWidth <= card.clientWidth + 1), clipped };
      });
      expect(layout, `editor at ${width}`).toEqual({ pageFits: true, mainFits: true, cardsFit: true, clipped: [] });
      for (const detail of await advanced.all()) await detail.locator("summary").click();
      await cards.first().screenshot({ path: test.info().outputPath(`editor-${chainCount}-${width}.png`) });
    }

    await page.getByLabel("proxy01-chain-1 middle provider", { exact: true }).focus();
    for (const label of ["middle region", "edge provider", "edge nodes", "default edge region", "edge 01 provider", "edge 01 region", "edge 01 size", "edge 02 provider", "edge 02 region", "edge 02 size"]) {
      await page.keyboard.press("Tab");
      await expect(page.getByLabel(`proxy01-chain-1 ${label}`, { exact: true })).toBeFocused();
    }
    await page.keyboard.press("Tab");
    await expect(cards.first().locator("summary")).toBeFocused();
    expect(api.applyPaths).toEqual([]);
    expect(api.unexpectedMutations).toEqual([]);
  });
}

async function mockCorePlanApi(page: Page, keyed = false, editorChainCount = 0) {
  const api = {
    prepareCount: 0,
    staleLifecycleReads: 0,
    planReadsById: {} as Record<string, number>,
    applyPaths: [] as string[],
    applyBodies: [] as unknown[],
    unexpectedMutations: [] as string[],
    createdRecordIds: [] as string[],
    cloudMutationRequests: [] as string[]
  };

  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();

    if (pathname === "/api/templates") return route.fulfill({ json: { templates: [template()] } });
    if (pathname === "/api/engagements" && method === "GET") {
      return route.fulfill({ json: { engagements: [engagement(keyed)] } });
    }
    if (pathname === `/api/engagements/${engagementId}` && method === "GET") {
      return route.fulfill({ json: { engagement: engagement(keyed, editorChainCount) } });
    }
    if (pathname === "/api/jobs") return route.fulfill({ json: { jobs: [] } });
    if (pathname === "/api/dashboard") return route.fulfill({ json: { dashboard: dashboard() } });
    if (pathname === "/api/health") return route.fulfill({ json: { service: "barragan-api", status: "ok" } });
    if (pathname === "/api/provider-catalog/sketch") {
      const provider = new URL(request.url()).searchParams.get("provider") ?? "linode";
      return route.fulfill({ json: { catalog: providerCatalog(provider, editorChainCount > 0) } });
    }
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/readiness") {
      return route.fulfill({ json: { readiness: readiness() } });
    }
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-stale-terminal") {
      api.staleLifecycleReads += 1;
      return route.fulfill({ json: { job: staleTerminalLifecycleJob() } });
    }
    if (pathname === "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-wi0266-active") {
      return route.fulfill({ json: { job: activeInfrastructureJob() } });
    }
    if (pathname === `/api/engagements/${engagementId}/operations`) {
      const deployed = api.applyBodies.length > 0;
      return route.fulfill({ json: { operations: deployed ? {
        ...operationsOverview(),
        lifecycle: { state: "active", label: "Active", attentionRequired: false, terminal: false },
        activeJob: activeInfrastructureJob(), coreJob: activeInfrastructureJob()
      } : operationsOverview() } });
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
    if (pathname === `/api/engagements/${engagementId}/revisions` && method === "GET") {
      return route.fulfill({ json: { revisions: [] } });
    }
    if (pathname === `/api/engagements/${engagementId}/deployment-plans/current`) {
      return route.fulfill({ json: { plan: null } });
    }
    if (pathname === `/api/engagements/${engagementId}/infrastructure` && method === "POST") {
      return route.fulfill({ json: { engagement: engagement(keyed) } });
    }
    if (pathname === `/api/engagements/${engagementId}/revisions` && method === "POST") {
      const revisionId = `rev-wi0266-${api.prepareCount + 1}`;
      return route.fulfill({ json: { revision: revision(revisionId) } });
    }
    if (pathname === `/api/engagements/${engagementId}/deployment-plans` && method === "POST") {
      api.prepareCount += 1;
      const plan = planForSequence(keyed ? 3 : api.prepareCount, keyed);
      return route.fulfill({ json: { plan: { ...plan, status: "preparing", stage: "terraform_plan" } } });
    }

    const planMatch = pathname.match(new RegExp(`^/api/engagements/${engagementId}/deployment-plans/(plan-[^/]+)$`));
    if (planMatch && method === "GET") {
      const planId = planMatch[1];
      api.planReadsById[planId] = (api.planReadsById[planId] ?? 0) + 1;
      return route.fulfill({ json: { plan: planById(planId, keyed) } });
    }
    if (pathname === `/api/engagements/${engagementId}/deployment-plans/plan-output-only/apply` && method === "POST") {
      api.applyPaths.push(pathname);
      api.applyBodies.push(request.postDataJSON());
      return route.fulfill({
        json: {
          plan: { ...planById("plan-output-only", keyed), status: "applied" },
          job: activeInfrastructureJob()
        }
      });
    }

    if (method !== "GET") api.unexpectedMutations.push(`${method} ${pathname}`);
    return route.fulfill({ json: {} });
  });

  return api;
}

function planForSequence(sequence: number, keyed = false) {
  if (sequence === 1) {
    return corePlan("plan-destructive", "ready", { add: 1, update: 0, replace: 1, remove: 0, read: 0, output: 0 }, [
      resourceChange("replace", "oci_core_instance.proxy01", "Proxy 01", "Compute")
    ]);
  }
  if (sequence === 2) {
    return corePlan("plan-no-changes", "no_changes", { add: 0, update: 0, replace: 0, remove: 0, read: 2, output: 0 }, []);
  }
  return corePlan("plan-output-only", "ready", { add: 0, update: 0, replace: 0, remove: 0, read: 0, output: 1 }, [
    resourceChange("output", "output.homebase_public_ip", "Homebase public IP", "Outputs")
  ], keyed);
}

function planById(planId: string, keyed = false) {
  if (planId === "plan-destructive") return planForSequence(1);
  if (planId === "plan-no-changes") return planForSequence(2);
  return planForSequence(3, keyed);
}

function corePlan(
  id: string,
  status: "ready" | "no_changes",
  counts: Record<string, number>,
  resourceChanges: Array<Record<string, string>>,
  keyed = false
) {
  return {
    id,
    engagementId,
    revisionId: `rev-${id}`,
    status,
    stage: status === "no_changes" ? "No Terraform changes" : "Terraform plan saved",
    counts,
    resourceChanges,
    target: { name: "barragan-testing", region: "us-ashburn-1" },
    reviewedConfiguration: {
      templateId: "standard-rti",
      templateName: "Standard RTI",
      core: { homebases: 1, proxies: 2, elkEnabled: false },
      target: { name: "barragan-testing", region: "us-ashburn-1" },
      sshSourceCidrs: ["160.34.86.0/23"],
      ...(keyed ? { sketchAuthorization: {
        kind: "bounded-post-core",
        provider: "digitalocean",
        providerConnectionId: "connection-do",
        image: "ubuntu-24-04-x64",
        source: { revision: "a".repeat(40), templateSha256: "b".repeat(64), providerLock: { path: ".terraform.lock.hcl", sha256: "c".repeat(64), digitaloceanVersion: "2.103.0" } },
        chains: ["proxy01", "proxy02"].map((proxy, index) => ({
          id: `persisted-chain-${index + 1}`,
          fingerprint: `fingerprint-${index + 1}`,
          assignedProxy: proxy,
          middle: { provider: "digitalocean", region: "sfo3", size: "s-1vcpu-1gb" },
          edges: [{ id: "edge-01", provider: "digitalocean", region: "sfo3", size: "s-1vcpu-1gb" }]
        })),
        firewall: {
          publicTcpPorts: ["80", "443", "2222"],
          publicUdpPorts: [],
          publicIpv6Allowed: false,
          managementSsh: { port: 22, sourceRule: "selected-proxy-public-ipv4-32", proxyNames: ["proxy01", "proxy02"] },
          peerIngress: { protocols: ["tcp", "udp", "icmp"], portRange: "1-65535", sourceRule: "all-created-middle-and-edge-public-ipv4-32" },
          outboundIpv4: [
            { protocol: "tcp", portRange: "1-65535", destination: "0.0.0.0/0" },
            { protocol: "udp", portRange: "1-65535", destination: "0.0.0.0/0" },
            { protocol: "icmp", destination: "0.0.0.0/0" }
          ]
        },
        fingerprint: "reviewed-scope"
      } } : {})
    },
    postCoreScope: {
      chainCount: 2,
      middleCount: 2,
      edgeCount: keyed ? 2 : 4,
      providers: keyed ? ["digitalocean"] : ["digitalocean", "linode"],
      chains: ["proxy01", "proxy02"].map((proxy, index) => ({
        id: `persisted-chain-${index + 1}`,
        intentId: `${proxy}-chain-1`,
        assignedProxy: proxy,
        middle: keyed
          ? { provider: "digitalocean", region: "sfo3", size: "s-1vcpu-1gb" }
          : { provider: "linode", region: "us-sea" },
        edges: (keyed ? [1] : [1, 2]).map((edge) => ({
          id: `edge-${String(edge).padStart(2, "0")}`,
          provider: "digitalocean",
          region: "sfo3",
          ...(keyed ? { size: "s-1vcpu-1gb" } : {})
        }))
      }))
    },
    preparedAt: "2026-08-05T14:00:00Z",
    ageWarningAt: "2099-08-05T15:00:00Z",
    sshSourceCidrs: ["160.34.86.0/23"],
    inputFingerprint: `fingerprint-${id}`,
    computeProfile: {
      id: "standard-rti",
      name: "Standard RTI",
      fingerprint: "a".repeat(64),
      bootVolumeSizeGiB: 512,
      roles: [
        { role: "homebase", label: "Homebase", nodeCount: 1, shape: "BM.Standard3.64", ocpus: 64, memoryGiB: 1024 },
        { role: "proxy", label: "Proxy", nodeCount: 2, shape: "VM.Standard.E4.Flex", ocpus: 2, memoryGiB: 32 },
        { role: "elk", label: "ELK", nodeCount: 0, shape: "VM.Standard.E4.Flex", ocpus: 2, memoryGiB: 32 }
      ]
    },
    sanitizedTextKind: "terraform_plan",
    sanitizedText: "Terraform used the selected providers to generate this execution plan.",
    terraformFiles: [],
    error: null
  };
}

function resourceChange(action: string, address: string, displayName: string, group: string) {
  return { action, address, type: "Terraform value", provider: "terraform", displayName, group, region: "us-ashburn-1" };
}

function template() {
  return {
    id: "standard-rti",
    name: "Standard RTI",
    version: "1",
    description: "Baseline RTI",
    defaultNodeGroups: ["homebase", "proxy01", "proxy02"],
    supportedProviders: ["oci"]
  };
}

function engagement(keyed = false, editorChainCount = 0) {
  return {
    id: engagementId,
    name: editorChainCount ? "Example fixture: responsive infrastructure" : "WI0266",
    status: "planned",
    owner: "operator",
    templateId: "standard-rti",
    activeRevision: null,
    sketchStateSchema: keyed ? "provider-keyed-v2" : "split-v1",
    inputParameters: editorChainCount ? {
      sketchChains: Array.from({ length: editorChainCount }, (_, index) => {
        const middle = providerCatalog(index % 2 ? "digitalocean" : "linode");
        const edge = providerCatalog(index % 2 ? "linode" : "digitalocean");
        return {
          assignedProxy: "proxy01",
          middleProvider: middle.provider, middleRegion: middle.defaults.region, middleSize: middle.defaults.size,
          edgeProvider: edge.provider, edgeRegion: edge.defaults.region, edgeSize: edge.defaults.size,
          edges: [1, 2].map((number) => ({ id: `edge-0${number}`, provider: edge.provider, region: edge.defaults.region, size: edge.defaults.size }))
        };
      })
    } : {}
  };
}

function revision(id: string) {
  return {
    id,
    engagementId,
    revisionNumber: 1,
    status: "compiled",
    templateId: "standard-rti",
    inputParameters: {},
    resolvedTopology: {},
    runIntent: [],
    validationGates: []
  };
}

function readiness() {
  return {
    target: {
      provider: "oci",
      name: "barragan-testing",
      compartmentId: "ocid1.compartment.oc1..testing",
      region: "us-ashburn-1",
      classification: "testing"
    },
    availableTargets: [{
      provider: "oci",
      name: "barragan-testing",
      compartmentId: "ocid1.compartment.oc1..testing",
      region: "us-ashburn-1",
      classification: "testing"
    }],
    confirmationToken,
    expectedInstanceDisplayNames: ["homebase", "proxy01", "proxy02"],
    expectedVcnDisplayName: "barragan",
    workspace: "/tmp/mock-wi0266",
    guardrails: { noTouchCompartments: ["RedTeam"] },
    topology: { vcnCidr: "192.168.0.0/16" },
    sshIngress: { defaultSourceCidrs: ["160.34.86.0/23"] }
  };
}

function providerCatalog(provider: string, longLabels = false) {
  const digitalocean = provider === "digitalocean";
  const region = digitalocean ? "sfo3" : "us-sea";
  const size = digitalocean ? "s-1vcpu-1gb" : "g6-nanode-1";
  return {
    provider,
    regions: [{ id: region, label: longLabels ? digitalocean ? "San Francisco 3 (sfo3)" : "Seattle, Washington (us-sea)" : region, available: true }],
    sizes: [{ id: size, label: longLabels ? digitalocean ? "Basic 1 GB" : "Nanode 1 GB" : size, available: true, regions: [],
      ...(longLabels ? { vcpus: 1, memoryMb: 1024, priceMonthly: 5 } : {}) }],
    defaults: { region, size },
    source: "mock",
    cachedAt: "",
    expiresAt: "",
    warnings: [],
    regionPolicy: { allowedRegions: [region], includeBlocked: false }
  };
}

function operationsOverview() {
  return {
    engagementId,
    lifecycle: { state: "not_deployed", label: "Not deployed", attentionRequired: false, terminal: false },
    housekeepingItems: "",
    activeJob: null,
    coreJob: {
      id: "job-stale-terminal",
      action: "pilot_standard_rti_guarded_execute",
      status: "succeeded",
      target: engagementId,
      createdAt: "2026-08-04T14:00:00Z"
    },
    healthSummary: { status: "unknown", detail: "", hostCount: 0, activeHostCount: 0, lastCheckedAt: null },
    coreInfrastructure: [],
    sketchInfrastructure: [],
    providerFindings: [],
    servicePlacements: [],
    outboundChannels: [],
    inboundChannels: [],
    sshConfig: { stanza: "", downloadName: "wi0266-ssh-config" }
  };
}

function staleTerminalLifecycleJob() {
  return {
    id: "job-stale-terminal",
    action: "pilot_standard_rti_guarded_execute",
    status: "succeeded",
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId, engagementName: "WI0266" },
    artifactRefs: [],
    events: [{
      sequence: 1,
      level: "info",
      message: "prior teardown verified clean",
      data: { mutationStatus: "destroyed", finalCleanupStatus: "verified_clean" }
    }]
  };
}

function activeInfrastructureJob() {
  return {
    id: "job-wi0266-active",
    action: "pilot_standard_rti_guarded_execute",
    status: "succeeded",
    targetType: "engagement",
    targetId: engagementId,
    requestedBy: "operator",
    input: { engagementId, engagementName: "WI0266" },
    artifactRefs: [],
    events: [{
      sequence: 1,
      level: "info",
      message: "deployment held for operator inspection",
      data: {
        mutationStatus: "deployed",
        ansibleStatus: "configured",
        finalCleanupStatus: "pending_operator_teardown"
      }
    }]
  };
}

function dashboard() {
  return {
    generatedAt: "2026-08-05T14:00:00Z",
    summary: {
      templates: 1,
      engagements: 1,
      activeEngagements: 0,
      jobRuns: 0,
      activeInfrastructure: 0,
      attention: 0,
      destroyed: 0,
      lastKnown: 0,
      orphanCandidates: 0,
      recentTeardowns: 0,
      recentArchives: 0
    },
    engagementOverview: { active: [], recentlyEnded: [], recentlyArchived: [], windowDays: 30 },
    systemHealth: {
      api: { status: "ok", detail: "mock", checkedAt: "2026-08-05T14:00:00Z" },
      database: { status: "ok", detail: "mock", uriScheme: "sqlite", path: "/tmp/mock", seedStatus: "mock" },
      disk: { status: "ok", detail: "mock", path: "/tmp", freeBytes: 1, totalBytes: 2, usedPercent: 50 },
      providers: { status: "not checked", detail: "mock", checkedAt: null }
    },
    inventory: [],
    orphanCandidates: [],
    reconciliation: { status: "local-records", detail: "mocked fixture" }
  };
}
