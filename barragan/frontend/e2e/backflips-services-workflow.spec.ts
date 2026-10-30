/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

test("Capabilities is the only workspace for Static Web, Custom Listener, and Backflips", async ({ page, request }) => {
  const engagementName = `bf${Date.now().toString().slice(-6)}`;
  const createResponse = await request.post("/api/engagements", {
    data: {
      name: engagementName,
      owner: "playwright"
    }
  });
  expect(createResponse.ok()).toBeTruthy();
  const created = await createResponse.json();
  const engagementId = created.engagement.id as string;

  await page.goto("/");
  await expect(page.getByText("ready")).toBeVisible();
  await page.getByLabel("Active engagement", { exact: true }).selectOption(engagementId);
  await expect(page.getByRole("button", { name: "Service Instances" })).toHaveCount(0);
  await page.getByRole("button", { name: "Capabilities" }).click();

  const capabilities = page.getByRole("region", { name: "Capabilities" });
  const configuration = page.getByRole("region", { name: "Capability configuration" });
  await expect(capabilities).toBeVisible();
  await expect(page.getByRole("heading", { name: /Service Instances|Services/ })).toHaveCount(0);

  const customListenerCapabilityRow = capabilities.getByRole("button", { name: /^Custom Listener configure/i });
  const customListenerCapabilityBox = await customListenerCapabilityRow.boundingBox();
  const customListenerCapabilityParentBox = await customListenerCapabilityRow.locator("..").boundingBox();
  expect(customListenerCapabilityBox).not.toBeNull();
  expect(customListenerCapabilityParentBox).not.toBeNull();
  expect(customListenerCapabilityBox!.width).toBeGreaterThan(customListenerCapabilityParentBox!.width * 0.8);
  expect(customListenerCapabilityBox!.height).toBeLessThan(120);

  await configuration.getByRole("button", { name: /Static Web/i }).click();
  const staticWeb = page.getByRole("region", { name: "Static web service workflow" });
  await expect(staticWeb).toBeVisible();
  await expect(staticWeb).toContainText("Manage proxy-local web listeners and content paths.");
  await expect(staticWeb.getByLabel("Static web service placements")).toContainText("No Static Web sites are configured yet.");
  await staticWeb.getByRole("button", { name: "Add Site" }).click();
  const siteConfiguration = staticWeb.getByRole("region", { name: "Site Configuration" });
  await expect(siteConfiguration.getByLabel("Web site name")).toBeVisible();
  await expect(siteConfiguration.getByRole("button", { name: "Preview Web Apply" })).toBeVisible();
  await expect(siteConfiguration.getByRole("button", { name: "Apply Static Web" })).toBeVisible();
  await staticWeb.getByRole("button", { name: "Close" }).click();

  await configuration.getByRole("button", { name: /Custom Listener/i }).click();
  const customListener = page.getByRole("region", { name: "Custom Listener workflow" });
  await expect(customListener).toBeVisible();
  await expect(customListener).toContainText("Barragan records the listener and validation contract. It does not start, stop, or execute the server process.");
  await expect(customListener.getByLabel("Custom Listener configurations")).toContainText("No Custom Listeners are tracked yet.");
  await customListener.getByRole("button", { name: "Add Custom Listener" }).click();
  const customListenerConfiguration = page.getByRole("region", { name: "Custom Listener Configuration" });
  await expect(customListenerConfiguration.getByLabel("Custom Listener name")).toBeVisible();
  await expect(customListenerConfiguration.getByLabel("Custom Listener protocol")).toBeVisible();
  await expect(customListenerConfiguration.getByRole("button", { name: "Save Custom Listener" })).toBeVisible();
  await customListenerConfiguration.getByRole("button", { name: "Cancel" }).click();
  await customListener.getByRole("button", { name: "Close" }).click();

  await expect(configuration.getByRole("button", { name: /Backflips/i })).toHaveCount(0);
  const backflipsCapabilityRow = capabilities.getByRole("button", { name: /^Backflips V2 configure/i });
  await expect(backflipsCapabilityRow).toHaveCount(1);
  await expect(backflipsCapabilityRow).toContainText("Backflips V2");
  await backflipsCapabilityRow.click();

  const workflow = page.getByRole("region", { name: "Backflips V2 capability workflow" });
  await expect(workflow).toBeVisible();
  await expect(workflow).toContainText("Install role and configuration prerequisites for operator-managed Backflips listeners.");
  await expect(workflow).toContainText("Barragan applies backflips_v2, installs the engagement transport identity, and configures the default middle.");
  await expect(workflow.getByLabel("Backflips proxy")).toHaveValue("proxy01");

  await expect(workflow.getByRole("button", { name: "Preview Prerequisites" })).toBeEnabled();
  await expect(workflow.getByRole("button", { name: "Apply Backflips Prerequisites" })).toBeDisabled();
  await workflow.getByLabel("Backflips confirmation").fill("apply-service-backflips");
  await expect(workflow.getByRole("button", { name: "Apply Backflips Prerequisites" })).toBeEnabled();

  await workflow.getByRole("button", { name: "Close" }).click();
  await expect(page.getByRole("button", { name: "Service Instances" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Generic Service" })).toHaveCount(0);
});
