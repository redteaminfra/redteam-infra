/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";

test("operator edits sketch chains grouped by proxy", async ({ page, request }) => {
  const engagementName = `tmpl${Date.now().toString().slice(-6)}`;
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
  await page.getByRole("button", { name: "Infrastructure" }).click();

  const editor = page.getByRole("region", { name: "Sketch chains by proxy" });
  await expect(editor).toBeVisible();
  const formWidth = await page.getByRole("region", { name: "Infrastructure customizations" }).evaluate((node) => node.getBoundingClientRect().width);
  const editorWidth = await editor.evaluate((node) => node.getBoundingClientRect().width);
  expect(editorWidth).toBeGreaterThan(formWidth * 0.9);
  const proxy01 = page.getByRole("region", { name: "proxy01 sketch chains" });
  const proxy02 = page.getByRole("region", { name: "proxy02 sketch chains" });
  await expect(proxy01).toContainText("1 chain");
  await expect(proxy02).toContainText("1 chain");
  await expect(proxy01.getByLabel("proxy01-chain-1 middle provider")).toBeVisible();
  await expect(proxy01.getByLabel("proxy01-chain-1 edge provider")).toBeVisible();
  await expect(proxy01.getByLabel("proxy01-chain-1 default edge region")).toBeVisible();
  await expect(proxy01.getByLabel("proxy01-chain-1 edge 01 region")).toBeVisible();
  await expect(proxy01.getByLabel("proxy01-chain-1 edge 02 region")).toBeVisible();
  await expect(proxy02.getByLabel("proxy02-chain-1 edge 01 region")).toBeVisible();
  await expect(proxy01.getByLabel("proxy01-chain-1 middle region")).toHaveJSProperty("tagName", "SELECT");
  await proxy01.getByText("Advanced sketch settings").click();
  await expect(proxy01.getByLabel("proxy01-chain-1 middle size")).toHaveJSProperty("tagName", "SELECT");
  await expect(proxy01.locator(".sketch-chain-card").first()).toBeVisible();
  const proxy01CardFits = await proxy01.locator(".sketch-chain-card").first().evaluate((node) => node.scrollWidth <= node.clientWidth + 1);
  expect(proxy01CardFits).toBeTruthy();
  await expect(page.getByLabel("Middle credential alias")).toHaveCount(0);
  await expect(page.getByLabel("Edge credential alias")).toHaveCount(0);

  await proxy01.getByLabel("proxy01-chain-1 edge provider").selectOption("linode");
  await expect(proxy01.getByLabel("proxy01-chain-1 default edge region")).toHaveValue("us-sea");
  await expect(proxy01.getByLabel("proxy01-chain-1 edge 01 region")).toHaveValue("us-sea");
  await proxy01.getByLabel("proxy01-chain-1 edge 02 region").selectOption("us-lax");
  await proxy01.getByLabel("proxy01-chain-1 edge nodes").fill("3");
  await expect(proxy01.getByLabel("proxy01-chain-1 edge 03 region")).toBeVisible();
  const review = page.getByRole("region", { name: "Core infrastructure plan review" });
  await expect(review).toBeVisible();
  await expect(page.getByRole("button", { name: "Show Review" })).toHaveCount(0);
  const postCore = page.getByRole("region", { name: "Validated post-core rollout" });
  await expect(postCore).toContainText("proxy01");
  await expect(postCore).toContainText("linode/us-lax edge");

  await proxy02.getByRole("button", { name: "Add Chain" }).click();
  await expect(proxy02).toContainText("2 chains");
  await expect(proxy02.getByLabel("proxy02-chain-2 middle region")).toBeVisible();
});
