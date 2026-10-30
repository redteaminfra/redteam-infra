/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { expect, test } from "@playwright/test";
import { readFile, stat } from "node:fs/promises";

async function example_operator_threePassword(): Promise<string> {
  const path = process.env.BARRAGAN_CODY_PASSWORD_FILE ?? `${process.env.HOME}/.sec/barragan_example_operator_three`;
  const metadata = await stat(path);
  if ((metadata.mode & 0o777) !== 0o600) throw new Error("Example Operator password file must have mode 0600");
  return (await readFile(path, "utf8")).replace(/[\r\n]+$/, "");
}

test("authenticated administrator can open personal controls in Global Settings", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByLabel("Active engagement", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Global Settings" }).click();
  await expect(page.getByRole("button", { name: "User" })).toHaveClass(/active/);
  await expect(page.getByLabel("User settings")).toContainText("example_operator_three");
  await expect(page.getByLabel("User settings")).toContainText("Administrator");
  await expect(page.getByRole("button", { name: "Change password" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out all sessions and tokens" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Cloud Providers" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Barragan App" })).toBeVisible();
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("heading", { name: "Change your password" })).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.getByLabel("Active engagement", { exact: true })).toBeVisible();
});

test("Example Operator can sign in and sign out through the browser", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ baseURL, storageState: undefined });
  const page = await context.newPage();
  await page.goto("/");
  await page.getByLabel("Username").fill("example_operator_three");
  await page.getByLabel("Password").fill(await example_operator_threePassword());
  await page.getByRole("button", { name: "Sign in" }).click();

  await page.getByRole("button", { name: "Global Settings" }).click();
  await expect(page.getByLabel("User settings")).toContainText("example_operator_three");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sign in to Barragan" })).toBeVisible();
  await context.close();
});

test("Global Settings tabs remain usable at a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await page.getByRole("button", { name: "Global Settings" }).click();
  await expect(page.getByLabel("User settings")).toBeVisible();
  await page.getByRole("button", { name: "Cloud Providers" }).click();
  await expect(page.getByLabel("Provider credentials")).toBeVisible();
  await page.getByRole("button", { name: "Barragan App" }).click();
  await expect(page.getByLabel("Barragan application settings")).toBeVisible();
});

test("a bootstrapped human is forced to choose a permanent password", async ({ browser, baseURL }) => {
  const username = "forced-change-user";
  const context = await browser.newContext({ baseURL, storageState: undefined });
  const page = await context.newPage();
  await page.route("**/api/auth/login", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        authRequired: true,
        authenticated: true,
        csrfToken: "forced-change-csrf",
        mustChangePassword: true,
        user: { id: "forced-change-user", username, displayName: "Forced Change User", roles: ["administrator"] }
      }),
      status: 200
    });
  });
  await page.route("**/api/auth/logout", async (route) => {
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ authenticated: false }), status: 200 });
  });
  await page.goto("/");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill("temporary-password");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByRole("heading", { name: "Choose a permanent password" })).toBeVisible();
  await expect(page.getByText(`Welcome, ${username}. Change the temporary password before continuing.`)).toBeVisible();
  await expect(page.getByLabel("Temporary password")).toBeVisible();
  await expect(page.getByLabel("New password", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Confirm new password")).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to Barragan" })).toBeVisible();
  await context.close();
});

test("personal settings wires a CSRF-protected sign-out-all request", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ baseURL, storageState: undefined });
  const page = await context.newPage();
  await page.goto("/");
  await page.getByLabel("Username").fill("example_operator_three");
  await page.getByLabel("Password").fill(await example_operator_threePassword());
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("button", { name: "Global Settings" }).click();
  // Backend tests prove real all-session revocation. Intercept this request so
  // browser acceptance cannot revoke the suite-wide Example Operator storage state used by
  // other Playwright files running in parallel.
  await page.route("**/api/auth/logout-all", async (route) => {
    expect(route.request().method()).toBe("POST");
    expect(route.request().headers()["x-barragan-csrf"]).toBeTruthy();
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ authenticated: false }), status: 200 });
  });
  await page.getByRole("button", { name: "Sign out all sessions and tokens" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to Barragan" })).toBeVisible();
  await context.close();
});
