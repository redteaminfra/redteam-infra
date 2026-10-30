/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

type OperationsOverview = {
  sketchInfrastructure: unknown[];
  outboundChannels: unknown[];
  inboundChannels: unknown[];
};

test("engagement Overview only renders recorded operations data", async ({ page, request }) => {
  await page.goto("/");

  const activeEngagement = page.getByLabel("Active engagement", { exact: true });
  await expect(activeEngagement).toBeVisible();
  await expect(page.getByText("ready")).toBeVisible();
  await expect.poll(() => activeEngagement.inputValue()).not.toBe("");
  const engagementId = await activeEngagement.inputValue();
  const response = await request.get(`/api/engagements/${engagementId}/operations`);
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  const operations = body.operations as OperationsOverview;

  await page.getByRole("button", { name: "Overview" }).click();

  const sketch = page.locator('[aria-label="Sketch infrastructure"]');
  const outbound = page.locator('[aria-label="Outbound Channels"]');
  const inbound = page.locator('[aria-label="Inbound Channels"]');

  if (operations.sketchInfrastructure.length === 0) {
    await expect(sketch).toContainText("No sketch middle or edge nodes are configured yet.");
  }
  if (operations.outboundChannels.length === 0) {
    await expect(outbound).toContainText("No outbound sketch channels are configured yet.");
  }
  if (operations.inboundChannels.length === 0) {
    await expect(inbound).toContainText("No inbound channels are configured yet.");
  }

  const recordedText = JSON.stringify(operations);
  const dashboard = page.getByRole("region", { name: "Engagement operations dashboard" });
  if (!recordedText.includes("chain-1-edge")) {
    await expect(dashboard).not.toContainText("chain-1-edge");
  }
  if (!recordedText.includes("example.invalid")) {
    await expect(dashboard).not.toContainText("example.invalid");
  }
});
