/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

for (const width of [760, 1280, 1920]) {
  test(`provider observations distinguish partial checks and protect unmanaged resources at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 950 });
    await page.route("**/api/**", async (route) => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith("/api/")) return route.continue();
      if (url.pathname === "/api/auth/session") return route.fulfill({ json: { authRequired: false, authenticated: true } });
      if (url.pathname === "/api/templates") return route.fulfill({ json: { templates: [] } });
      if (url.pathname === "/api/engagements") return route.fulfill({ json: { engagements: [] } });
      if (url.pathname === "/api/dashboard") return route.fulfill({ json: { dashboard: inventoryFixture(url.searchParams.get("live") === "1") } });
      return route.fulfill({ json: {} });
    });
    await page.goto("/");
    const inventory = page.getByRole("article", { name: "Current provider inventory", exact: true });
    await expect(inventory).toContainText("not checked");
    await expect(inventory).toContainText("does not prove resources are absent");
    await page.getByRole("button", { name: "Refresh Provider Inventory", exact: true }).click();
    await expect(inventory).toContainText("partial");
    await expect(inventory).toContainText("Cached observation");
    await expect(inventory).toContainText("Matches deployment records");
    await expect(inventory).toContainText("Unmanaged — protected");
    await expect(inventory).toContainText("Boot volumes");
    await expect(inventory).toContainText("Firewalls");
    await expect(inventory.getByText("Read-only observation — protected", { exact: true })).toHaveCount(3);
    await expect(inventory).toContainText("disabled");
    await expect(inventory).toContainText("6ef4a404-68c2-44c7-af17-2d5d45ee56ef");
    await expect(inventory).toContainText("not a complete billing inventory");
    await expect(inventory.getByRole("button")).toHaveCount(0);
    await expect(inventory.getByRole("region", { name: "linode inventory check" })).toContainText("Instance list failed");
    await inventory.scrollIntoViewIfNeeded();
    const clipped = await inventory.evaluate((element) => Array.from(element.querySelectorAll("p, h3, h4, dt, dd, strong")).filter((child) => child.scrollWidth > child.clientWidth + 2).map((child) => child.textContent));
    expect(clipped).toEqual([]);
    await inventory.evaluate((element) => element.scrollIntoView({ block: "start" }));
    expect(await inventory.evaluate((element) => {
      const bounds = element.getBoundingClientRect();
      return bounds.left >= 0 && bounds.right <= window.innerWidth;
    })).toBe(true);
    await page.screenshot({ path: test.info().outputPath(`provider-inventory-${width}-top.png`) });
    await inventory.getByRole("heading", { name: "Retained boot volume", exact: true }).evaluate((element) => element.scrollIntoView({ block: "start" }));
    await page.screenshot({ path: test.info().outputPath(`provider-inventory-${width}-resources.png`) });
  });
}

function inventoryFixture(live: boolean) {
  const observation = "2026-10-22T12:00:00Z";
  return {
    generatedAt: "2026-10-22T12:00:30Z",
    summary: { templates: 0, engagements: 0, activeEngagements: 0, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0 },
    engagementOverview: { active: [], recentlyEnded: [], recentlyArchived: [], windowDays: 30 },
    systemHealth: Object.fromEntries(["api", "database", "disk", "providers"].map((name) => [name, { status: name === "providers" ? "attention" : "ok", detail: "Controlled test fixture" }])),
    inventory: [], orphanCandidates: [], reconciliation: { status: "local-records", detail: "Controlled test fixture" },
    providerDiscovery: {
      status: live ? "partial" : "not_checked", observedAt: live ? observation : null, cached: live, ageSeconds: live ? 30 : null,
      detail: live ? "Some provider reads were incomplete. Results do not prove absence." : "Provider inventory not checked.",
      providers: live ? [
        { provider: "oci", status: "partial", observedAt: observation, resourceCount: 3, coverage: ["compute_instance", "vcn", "subnet", "internet_gateway", "route_table", "security_list", "boot_volume"], detail: "One resource type could not be checked." },
        { provider: "linode", status: "partial", observedAt: observation, resourceCount: 1, coverage: ["instance", "firewall"], detail: "Instance list failed; firewall observations retained. Coverage is incomplete." },
        { provider: "digitalocean", status: "checked", observedAt: observation, resourceCount: 1, coverage: ["droplet", "firewall"], detail: "Droplet and firewall inventory checked." }
      ] : []
    },
    providerInventory: live ? [["recorded", "unmanaged_rti"].map((classification, index) => ({
      provider: "oci", resourceType: "compute_instance", resourceId: `ocid1.instance.oc1.test.${"x".repeat(100)}${index}`,
      name: index ? "homebase-unmanaged" : "homebase-matched", region: "us-sanjose-1", lifecycleState: "RUNNING", engagementId: "eng-fixture",
      engagementName: "Fixture", source: "oci_cli", classification, barraganOwned: !index, observedAt: observation, actions: []
    })), [
      { provider: "oci", resourceType: "boot_volume", resourceId: `ocid1.bootvolume.oc1.test.${"b".repeat(100)}`, name: "Retained boot volume", region: "us-sanjose-1", lifecycleState: "AVAILABLE", barraganOwned: true },
      { provider: "linode", resourceType: "firewall", resourceId: "987654", name: "Opaque firewall", region: "", lifecycleState: "disabled", barraganOwned: false },
      { provider: "digitalocean", resourceType: "firewall", resourceId: "6ef4a404-68c2-44c7-af17-2d5d45ee56ef", name: "Inspector firewall", region: "", lifecycleState: "succeeded", barraganOwned: false }
    ].map((resource) => ({ ...resource, classification: "observation_only", source: "fixture", engagementId: "", engagementName: "", observedAt: observation, actions: [] }))].flat() : []
  };
}
