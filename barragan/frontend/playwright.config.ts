/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { defineConfig, devices } from "@playwright/test";
import { authStatePath, baseURL } from "./playwright.runtime";

const chromeExecutablePath = process.env.PLAYWRIGHT_CHROME_EXECUTABLE_PATH ?? "/usr/bin/google-chrome";
const video = process.env.PLAYWRIGHT_VIDEO === "off" ? "off" : "retain-on-failure";

export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/auth.setup.ts",
  globalTeardown: "./e2e/auth.teardown.ts",
  timeout: 30_000,
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL,
    storageState: authStatePath,
    headless: process.env.PLAYWRIGHT_HEADLESS !== "0",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video
  },
  projects: [
    {
      name: "chrome",
      use: {
        ...devices["Desktop Chrome"],
        channel: undefined,
        launchOptions: {
          executablePath: chromeExecutablePath
        }
      }
    }
  ]
});
