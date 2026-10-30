/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const source = readFileSync("scripts/initial-load-performance.mjs", "utf8");

describe("initial-load performance sample isolation", () => {
  it("registers exact auxiliary waits before navigation and drains them after usable-ready capture", () => {
    expect(source).toContain('const auxiliaryEndpoints = ["/api/templates", "/api/engagements?scope=all"]');

    const registerWaitsAt = source.indexOf('cdp.on("Network.requestWillBeSent"');
    const navigateAt = source.indexOf("await page.goto(");
    const captureReadyAt = source.indexOf("const observed = await page.evaluate");
    const freezeUsableAt = source.indexOf("const usableMs = observed.readyAt + validationProbeMs");
    const drainAt = source.indexOf('await page.waitForLoadState("networkidle"');
    const closeAt = source.indexOf("await page.close()");

    expect(registerWaitsAt).toBeGreaterThan(-1);
    expect(registerWaitsAt).toBeLessThan(navigateAt);
    expect(captureReadyAt).toBeLessThan(freezeUsableAt);
    expect(freezeUsableAt).toBeLessThan(drainAt);
    expect(drainAt).toBeLessThan(closeAt);
    expect(source).toContain('cdp.on("Network.loadingFinished"');
    expect(source).toContain('cdp.on("Network.loadingFailed"');
    expect(source).toContain("const unsettledApiRequests = [...apiRequests.values()].filter((request) => !request.settled)");
    expect(source).toContain("const failedApiRequests = [...apiRequests.values()].filter");
  });

  it("keeps drain diagnostics separate from usable time in the raw sample", () => {
    expect(source).toMatch(/return \{\s*usableMs,\s*validationProbeMs,\s*usableReadyApiResources: preReadyApiResources,\s*postReadyDrainMs,\s*auxiliary,/);
    expect(source).toContain("status: request.status");
    expect(source).toContain("durationMs: request.durationMs");
    expect(source).toContain(".filter((request) => request.startedAtWallMs < readyAtWallMs)");
    expect(source).toContain('const expectedPreReadyApiResources = ["/api/auth/session", "/api/dashboard"].sort()');
    expect(source).toContain("const expectedPostReadyApiResources = [...auxiliaryEndpoints].sort()");
    expect(source).not.toContain("usableMs: observed.readyAt + validationProbeMs + postReadyDrainMs");
  });
});
