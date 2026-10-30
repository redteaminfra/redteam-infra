/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

test("engagement Infrastructure page exposes operator progress", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Barragan" })).toBeVisible();
  await page.getByRole("button", { name: "Infrastructure" }).click();

  await expect(page.getByRole("heading", { name: "1. Select Template And Customizations" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "2. Review Infrastructure Plan" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "3. Deploy Infrastructure" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Prepare Infrastructure Plan" })).toHaveCount(1);

  const deploymentProgress = page.getByRole("region", { name: "Deployment progress" });
  const teardownProgress = page.getByRole("region", { name: "Teardown progress" });
  const visibleProgress = deploymentProgress.or(teardownProgress);

  await expect(visibleProgress).toBeVisible();
  await expect(visibleProgress.getByText("Step 1", { exact: true })).toBeVisible();

  const progressText = await visibleProgress.innerText();
  expect(progressText).toMatch(/Load readiness boundary|Tear down requested/);

  const activityStatus = await visibleProgress.locator(".section-heading > span").innerText();
  const activeSteps = visibleProgress.locator(".deployment-step.active");
  const wipSteps = visibleProgress.locator(".deployment-step.wip");
  const activeCount = await activeSteps.count();
  const wipCount = await wipSteps.count();
  if (activityStatus === "deploying" || activityStatus === "tearing down") {
    expect(activeCount + wipCount).toBeGreaterThan(0);
  }

  if (activityStatus === "verified_clean" || activityStatus === "verified clean") {
    await expect(visibleProgress.getByText("Verify cleanup")).toBeVisible();
  }

  await expect(page.getByRole("region", { name: "Infrastructure customizations" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Channel configuration" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Outbound channel workflow" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Inbound channel workflow" })).toHaveCount(0);
  const chainLifecycle = page.getByRole("region", { name: "Live sketch chain lifecycle" });
  await expect(chainLifecycle).toBeVisible();
  await expect(chainLifecycle.getByRole("button", { name: "Add proxy01 Chain" })).toBeVisible();
  await expect(chainLifecycle.getByRole("button", { name: "Add proxy02 Chain" })).toBeVisible();
  await expect(chainLifecycle.getByText("Marking a chain burned only records operator state")).toBeVisible();
  const advancedSafety = page.getByText("Advanced deployment safety settings");
  await expect(advancedSafety).toBeVisible();
  await expect(page.getByLabel("SSH allowed CIDRs")).not.toBeVisible();
  await advancedSafety.click();
  await expect(page.getByLabel("SSH allowed CIDRs")).toBeVisible();
  await expect(page.getByRole("region", { name: "Infrastructure deployment" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Sketch deployment activity" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sketch infrastructure" })).toBeVisible();
  await expect(page.getByText("Linode sketch deployment")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Deploy Sketch Infrastructure" })).toHaveCount(0);
  await expect(page.getByText("Barragan provisions sketch nodes with provider APIs and Terraform")).toBeVisible();
  const lifecycle = page.getByRole("region", { name: "Infrastructure lifecycle" });
  await expect(lifecycle).toBeVisible();
  await expect(lifecycle.getByRole("button", { name: "Start Instances" })).toBeDisabled();
  await expect(lifecycle.getByRole("button", { name: "Stop Instances" })).toBeDisabled();
  await expect(lifecycle.getByRole("button", { name: "Archive Deployment" })).toBeDisabled();
  await expect(lifecycle.getByRole("button", { name: "Tear Down Infrastructure" })).toBeVisible();
});
