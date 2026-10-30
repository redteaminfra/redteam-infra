/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

const lifecycle = (state: string, label: string, terminal: boolean) => ({
  state,
  label,
  attentionRequired: state === "cleanup_required" || state === "unknown",
  terminal,
  administrativeStatus: "planned",
  evidence: [{ kind: "core_job", id: "job-opaque", status: "succeeded" }],
  evidenceFingerprint: `fingerprint-${state}`,
  reconciledAt: "2026-07-31T12:00:00+00:00"
});

test("Global and Operations use operational lifecycle and local reconciliation", async ({ page }) => {
  let reconciliations = 0;
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/templates") {
      return route.fulfill({ json: { templates: [] } });
    }
    if (path === "/api/engagements" && request.method() === "GET") {
      return route.fulfill({ json: { engagements: [{
        id: "eng-opaque", name: "Lifecycle Example", status: "planned", owner: "operator",
        templateId: null, activeRevision: null, description: "", documentationUrl: "", jiraUrl: "",
        lifecycle: lifecycle("active", "Active", false)
      }] } });
    }
    if (path === "/api/engagements/eng-opaque/lifecycle/reconcile") {
      reconciliations += 1;
      return route.fulfill({ json: { reconciliation: {
        previous: lifecycle("active", "Active", false),
        current: lifecycle("destroyed", "Destroyed", true),
        changed: true
      } } });
    }
    if (path === "/api/engagements/eng-opaque/operations") {
      return route.fulfill({ json: { operations: {
        engagementId: "eng-opaque", lifecycle: lifecycle("active", "Active", false),
        housekeepingItems: "", activeJob: null, coreJob: null,
        healthSummary: { status: "unknown", detail: "", hostCount: 0, activeHostCount: 0 },
        coreInfrastructure: [], sketchInfrastructure: [], providerFindings: [], servicePlacements: [],
        outboundChannels: [], inboundChannels: [], sshConfig: { stanza: "" }
      } } });
    }
    if (path === "/api/dashboard") {
      return route.fulfill({ json: { dashboard: null } });
    }
    return route.fulfill({ json: {} });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Overview" }).click();
  await expect(page.getByText("Infrastructure lifecycle")).toBeVisible();
  await expect(page.getByText("Active", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Engagements" }).click();
  const table = page.getByRole("region", { name: "Engagement metadata list" });
  await expect(table).toContainText("Active");
  await expect(table).toContainText("Record: planned");
  await expect(table.getByRole("button", { name: "Archive" })).toBeDisabled();
  await expect(table.getByRole("button", { name: "Retire" })).toBeDisabled();
  await expect(table).toContainText("Tear down infrastructure and verify cleanup");

  await table.getByRole("button", { name: "Reconcile" }).click();
  await expect(table).toContainText("Destroyed");
  await expect(table.getByRole("button", { name: "Archive" })).toBeEnabled();
  expect(reconciliations).toBe(1);
});

test("Current keeps archived infrastructure attention visible", async ({ page }) => {
  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/templates") return route.fulfill({ json: { templates: [] } });
    if (path === "/api/engagements") {
      return route.fulfill({ json: { engagements: [{
        id: "eng-archived", name: "Archived attention", status: "archived", owner: "operator",
        templateId: null, activeRevision: null, description: "", documentationUrl: "", jiraUrl: "",
        lifecycle: { ...lifecycle("cleanup_required", "Cleanup required", false), administrativeStatus: "archived" }
      }] } });
    }
    return route.fulfill({ json: {} });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Engagements" }).click();
  const table = page.getByRole("region", { name: "Engagement metadata list" });
  await expect(table).toContainText("Archived attention");
  await expect(table).toContainText("Resolve the owned-resource cleanup");
  await expect(table.getByRole("button", { name: "Archive" })).toBeDisabled();
  await expect(table.getByRole("button", { name: "Retire" })).toBeDisabled();

  await page.getByRole("button", { name: "Archived" }).click();
  await expect(table).toContainText("Archived attention");
});
