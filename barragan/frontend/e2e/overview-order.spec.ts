/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

test("engagement Overview presents operations panels in operator workflow order", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Overview" }).click();
  const dashboard = page.getByRole("region", { name: "Engagement operations dashboard" });
  await expect(dashboard).toBeVisible();

  const headings = await dashboard.locator("h3").allTextContents();
  expect(headings.slice(0, 7)).toEqual([
    "Red team infrastructure status",
    "Housekeeping Items",
    "Core Infrastructure",
    "Sketch Infrastructure",
    "Outbound Channels",
    "Inbound Channels",
    "SSH config"
  ]);
});
