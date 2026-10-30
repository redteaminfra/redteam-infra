/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

for (const initialFailure of [false, true]) {
  test(`Jobs survives navigation during its initial ${initialFailure ? "failed" : "successful"} request`, async ({ page }) => {
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const offsets: number[] = [];
    await page.route("**/api/**", async (route) => {
      const url = new URL(route.request().url());
      if (!url.pathname.startsWith("/api/")) return route.continue();
      if (url.pathname === "/api/auth/session") return route.fulfill({ json: { authRequired: false, authenticated: true } });
      if (url.pathname === "/api/templates") return route.fulfill({ json: { templates: [] } });
      if (url.pathname === "/api/engagements") return route.fulfill({ json: { engagements: [] } });
      if (url.pathname === "/api/dashboard") return route.fulfill({ json: { dashboard } });
      if (url.pathname === "/api/jobs") {
        const offset = Number(url.searchParams.get("offset") ?? 0);
        offsets.push(offset);
        if (offsets.length === 1) {
          await pending;
          if (initialFailure) return route.fulfill({ status: 503, json: { error: "temporarily unavailable" } });
        }
        return route.fulfill({ json: {
          jobs: [{ id: `job-page-${offset}`, action: `page-${offset}-result`, target: "test fixture", status: "succeeded", createdAt: "2026-10-22T12:00:00Z" }],
          pagination: { offset, limit: 50, total: 51, hasMore: offset === 0 }
        } });
      }
      return route.fulfill({ json: {} });
    });
    await page.goto("/");
    await page.getByRole("button", { name: "Jobs", exact: true }).click();
    await expect(page.getByText("Loading job summaries.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: "Jobs", exact: true }).click();
    release();
    const jobs = page.getByRole("region", { name: "Jobs", exact: true });
    if (initialFailure) {
      await expect(jobs.getByText("Job history unavailable", { exact: true })).toBeVisible();
      await expect(jobs.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
      await jobs.getByRole("button", { name: "Refresh", exact: true }).click();
    }
    await expect(jobs.getByRole("button", { name: "Select job job-page-0", exact: true })).toBeVisible();
    expect(offsets).toEqual(initialFailure ? [0, 0] : [0]);
    await jobs.getByRole("button", { name: "Next", exact: true }).click();
    await expect(jobs.getByRole("button", { name: "Select job job-page-50", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Dashboard", exact: true }).click();
    await page.getByRole("button", { name: "Jobs", exact: true }).click();
    await jobs.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect.poll(() => offsets.at(-1)).toBe(50);
    await expect(jobs.getByRole("button", { name: "Select job job-page-50", exact: true })).toBeVisible();
  });
}

const dashboard = {
  generatedAt: "2026-10-22T12:00:00Z",
  summary: { templates: 0, engagements: 0, activeEngagements: 0, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0, recentTeardowns: 0, recentArchives: 0 },
  engagementOverview: { active: [], recentlyEnded: [], recentlyArchived: [], windowDays: 30 },
  systemHealth: {
    api: { status: "ok", detail: "Fixture API" }, database: { status: "ok", detail: "Fixture database" }, disk: { status: "ok", detail: "Fixture disk" },
    providers: { status: "not checked", detail: "Fixture only", checkedAt: null }
  },
  inventory: [], orphanCandidates: [], reconciliation: { status: "local-records", detail: "Fixture only" }
};
