/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(frontendRoot, "..");
const baseUrlValue = process.env.BARRAGAN_PERF_BASE_URL;
if (!baseUrlValue) throw new Error("BARRAGAN_PERF_BASE_URL is required");
const baseUrl = new URL(baseUrlValue);
if (!["127.0.0.1", "localhost", "::1"].includes(baseUrl.hostname) || baseUrl.port !== "5174") {
  throw new Error("BARRAGAN_PERF_BASE_URL must use the documented loopback devtest target on port 5174; production port 5173 is rejected");
}
if (process.env.BARRAGAN_PERF_PROFILE !== "devtest-isolated") throw new Error("BARRAGAN_PERF_PROFILE=devtest-isolated is required; production and pre-fix profiles are rejected");
if (!process.env.BARRAGAN_PERF_STORAGE_STATE) throw new Error("BARRAGAN_PERF_STORAGE_STATE is required");
const expectedDatabasePath = process.env.BARRAGAN_PERF_EXPECTED_DATABASE_PATH;
if (!expectedDatabasePath) throw new Error("BARRAGAN_PERF_EXPECTED_DATABASE_PATH is required to bind measurements to the isolated server fixture");
const expectedEngagementNames = (process.env.BARRAGAN_PERF_EXPECTED_ENGAGEMENT_NAMES ?? "").split(",").map((value) => value.trim()).filter(Boolean).sort();
if (!expectedEngagementNames.length) throw new Error("BARRAGAN_PERF_EXPECTED_ENGAGEMENT_NAMES is required");
const expectedEngagements = Number.parseInt(process.env.BARRAGAN_PERF_EXPECTED_ENGAGEMENTS ?? "", 10);
const expectedJobs = Number.parseInt(process.env.BARRAGAN_PERF_EXPECTED_JOBS ?? "", 10);
if (!Number.isInteger(expectedEngagements) || !Number.isInteger(expectedJobs)) throw new Error("BARRAGAN_PERF_EXPECTED_ENGAGEMENTS and BARRAGAN_PERF_EXPECTED_JOBS are required");
const samples = Number.parseInt(process.env.BARRAGAN_PERF_SAMPLES ?? "30", 10);
if (!Number.isInteger(samples) || samples < 30) throw new Error("BARRAGAN_PERF_SAMPLES must be an integer of at least 30");
const outputPath = path.resolve(
  process.env.BARRAGAN_PERF_OUTPUT ?? path.join(repositoryRoot, "harness", "artifacts", `wi0269-initial-load-${Date.now()}.json`)
);

const launchOptions = process.env.PLAYWRIGHT_CHROME_EXECUTABLE_PATH
  ? { executablePath: process.env.PLAYWRIGHT_CHROME_EXECUTABLE_PATH }
  : {};
const browser = await chromium.launch({ headless: true, ...launchOptions });
const context = await browser.newContext({
  storageState: process.env.BARRAGAN_PERF_STORAGE_STATE || undefined,
  serviceWorkers: "block"
});

try {
  const preflight = await productionRuntimePreflight(context);
  const pairs = [];
  for (let index = 0; index < samples; index += 1) {
    const cold = await measureState(context, "cold", index, {}, preflight.assets);
    const requiredAssets = [...new Set(cold.requests.filter((request) => /\.(?:js|css)(?:\?|$)/.test(request.url)).map((request) => request.url))];
    const coldAssetEvidence = requiredAssets.map((asset) => cold.requests.find((request) => request.url === asset));
    if (coldAssetEvidence.some((request) => !request || request.status !== 200 || request.fromDiskCache || request.encodedDataLength <= 0)) {
      throw new Error("every dynamically observed cold JS/CSS asset must be a full status-200 network transfer");
    }
    const validators = Object.fromEntries(
      cold.requests
        .filter((request) => /\.(?:js|css)(?:\?|$)/.test(request.url))
        .map((request) => [request.url, { etag: request.headers.etag, lastModified: request.headers["last-modified"] }])
        .filter(([, value]) => value.etag || value.lastModified)
    );
    if (Object.keys(validators).length !== requiredAssets.length) {
      throw new Error("every expected hashed JS/CSS asset must expose ETag or Last-Modified");
    }
    const validated = await measureState(context, "validated", index, validators, requiredAssets);
    const warm = await measureState(context, "warm", index, {}, requiredAssets);
    const validatedAssets = [...new Set(validated.requests.filter((request) => /\.(?:js|css)(?:\?|$)/.test(request.url)).map((request) => request.url))].sort();
    const warmAssets = [...new Set(warm.requests.filter((request) => /\.(?:js|css)(?:\?|$)/.test(request.url)).map((request) => request.url))].sort();
    const coldAssets = [...requiredAssets].sort();
    if (JSON.stringify(coldAssets) !== JSON.stringify(validatedAssets) || JSON.stringify(coldAssets) !== JSON.stringify(warmAssets)) {
      throw new Error(`JS/CSS resource sets differ by cache state: cold=${coldAssets} validated=${validatedAssets} warm=${warmAssets}`);
    }
    pairs.push({ index, cold, validated, warm });
    process.stdout.write(`pair ${index + 1}/${samples}: cold=${cold.usableMs.toFixed(1)}ms validated=${validated.usableMs.toFixed(1)}ms warm=${warm.usableMs.toFixed(1)}ms\n`);
  }

  const raw = {
    schemaVersion: 1,
    recordedAt: new Date().toISOString(),
    baseUrl: baseUrl.origin,
    sampleCount: samples,
    percentileMethod: "nearest-rank",
    preflight,
    environment: environmentMetadata(),
    browser: { version: browser.version(), engine: "chromium", launchOptions },
    build: buildMetadata(preflight.assets),
    competingLoadPolicy: process.env.BARRAGAN_PERF_COMPETING_LOAD_POLICY ?? "isolated fixture; no intentional competing load",
    pairs,
    summary: summarize(pairs)
  };
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(raw, null, 2)}\n`, "utf8");
  process.stdout.write(`raw artifact: ${outputPath}\n${JSON.stringify(raw.summary, null, 2)}\n`);
} finally {
  await context.close();
  await browser.close();
}

async function productionRuntimePreflight(browserContext) {
  const response = await browserContext.request.get(baseUrl.href);
  if (!response.ok()) throw new Error(`runtime preflight failed: ${response.status()} ${baseUrl.href}`);
  const html = await response.text();
  const devSignatures = ["/@vite/client", "vite-hmr", "react-refresh", "__vite__"];
  const signature = devSignatures.find((candidate) => html.toLowerCase().includes(candidate.toLowerCase()));
  if (signature) throw new Error(`refusing Vite/HMR runtime: found ${signature}`);
  const assets = [...html.matchAll(/(?:src|href)=["']([^"']*\/assets\/[^"']+\.(?:js|css))["']/g)].map((match) => new URL(match[1], baseUrl).href);
  if (!assets.length || assets.some((asset) => !/-[a-zA-Z0-9_-]{6,}\.(?:js|css)(?:\?|$)/.test(asset))) {
    throw new Error("preflight requires content-hashed built assets; the target does not look like the production runtime");
  }
  const assetBindings = [];
  for (const asset of assets) {
    const remote = await browserContext.request.get(asset);
    if (!remote.ok()) throw new Error(`built asset preflight failed: ${remote.status()} ${asset}`);
    const remoteBody = await remote.body();
    const remoteBytes = remoteBody.byteLength;
    const localPath = path.join(frontendRoot, "dist", "assets", path.basename(new URL(asset).pathname));
    const localBytes = statSync(localPath).size;
    if (remoteBytes !== localBytes) throw new Error(`remote asset does not match clean local build: ${asset}`);
    const remoteSha256 = createHash("sha256").update(remoteBody).digest("hex");
    const localSha256 = createHash("sha256").update(readFileSync(localPath)).digest("hex");
    if (remoteSha256 !== localSha256) throw new Error(`remote asset content differs from clean local build: ${asset}`);
    assetBindings.push({ url: asset, bytes: remoteBytes, sha256: remoteSha256 });
  }
  const health = await browserContext.request.get(new URL("/api/health", baseUrl).href);
  if (!health.ok()) throw new Error(`health preflight failed: ${health.status()}`);
  const session = await browserContext.request.get(new URL("/api/auth/session", baseUrl).href);
  if (!session.ok()) throw new Error(`authenticated dev/test preflight failed: ${session.status()}`);
  const sessionBody = await session.json();
  if (sessionBody.authenticated !== true || !sessionBody.user || typeof sessionBody.user !== "object" || !sessionBody.user.id) {
    throw new Error("storage state must report authenticated=true with a valid user");
  }
  const healthBody = await health.json();
  if (healthBody.database?.path !== expectedDatabasePath) throw new Error(`server fixture database mismatch: ${healthBody.database?.path}`);
  const engagementsResponse = await browserContext.request.get(new URL("/api/engagements?scope=all", baseUrl).href);
  if (!engagementsResponse.ok()) throw new Error(`fixture identity request failed: ${engagementsResponse.status()}`);
  const observedEngagementNames = (await engagementsResponse.json()).engagements.map((engagement) => engagement.name).sort();
  if (JSON.stringify(observedEngagementNames) !== JSON.stringify(expectedEngagementNames)) throw new Error(`server fixture engagement identity mismatch: ${observedEngagementNames.join(",")}`);
  if (execFileSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: repositoryRoot, encoding: "utf8" }).trim()) throw new Error("performance runs require a clean tracked and untracked tree");
  return {
    status: response.status(),
    server: response.headers().server ?? null,
    assets, assetBindings,
    health: healthBody, authenticated: true,
    fixture: { expectedEngagements, expectedJobs, expectedEngagementNames, expectedDatabasePath }
  };
}

async function measureState(browserContext, cacheState, index, validators = {}, expectedAssetUrls = []) {
  const page = await browserContext.newPage();
  const auxiliaryEndpoints = ["/api/templates", "/api/engagements?scope=all"];
  await page.addInitScript(() => {
    window.__barraganPerf = { readyAt: null, longTasks: [] };
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) window.__barraganPerf.longTasks.push({ startTime: entry.startTime, duration: entry.duration });
    }).observe({ type: "longtask", buffered: true });
    const observe = () => {
      const record = () => {
        const marker = document.querySelector("[data-barragan-dashboard-ready='true']");
        if (marker && window.__barraganPerf.readyAt === null) {
          window.__barraganPerf.readyAt = performance.now();
          window.__barraganPerf.generatedAt = marker.getAttribute("data-dashboard-generated-at");
        }
      };
      new MutationObserver(record).observe(document.documentElement, { childList: true, subtree: true, attributes: true });
      record();
    };
    document.documentElement ? observe() : document.addEventListener("DOMContentLoaded", observe, { once: true });
  });

  const cdp = await page.context().newCDPSession(page);
  await cdp.send("Network.enable");
  if (cacheState === "cold") {
    await cdp.send("Network.setCacheDisabled", { cacheDisabled: true });
    await cdp.send("Network.clearBrowserCache");
    await cdp.send("Network.setCacheDisabled", { cacheDisabled: false });
  } else {
    await cdp.send("Network.setCacheDisabled", { cacheDisabled: false });
  }

  const validationStartedAt = performance.now();
  const validationProbes = cacheState === "validated"
    ? await runValidationProbes(browserContext, validators)
    : [];
  const validationProbeMs = cacheState === "validated" ? performance.now() - validationStartedAt : 0;
  const requests = new Map();
  const requestHeaders = new Map();
  const apiRequests = new Map();
  cdp.on("Network.requestWillBeSent", ({ requestId, request, timestamp, wallTime }) => {
    requestHeaders.set(requestId, { ...(requestHeaders.get(requestId) ?? {}), ...lowerCaseKeys(request.headers) });
    const url = new URL(request.url);
    if (url.origin === baseUrl.origin && url.pathname.startsWith("/api/")) {
      apiRequests.set(requestId, {
        endpoint: `${url.pathname}${url.search}`,
        url: request.url,
        startedAtWallMs: wallTime * 1_000,
        startedAtMonotonic: timestamp,
        status: null,
        settled: false,
        failed: null,
        durationMs: null,
      });
    }
  });
  cdp.on("Network.requestWillBeSentExtraInfo", ({ requestId, headers }) => requestHeaders.set(requestId, { ...(requestHeaders.get(requestId) ?? {}), ...lowerCaseKeys(headers) }));
  cdp.on("Network.responseReceived", ({ requestId, response }) => {
    requests.set(requestId, {
      url: response.url,
      status: response.status,
      mimeType: response.mimeType,
      fromDiskCache: Boolean(response.fromDiskCache),
      fromServiceWorker: Boolean(response.fromServiceWorker),
      headers: redactHeaders(lowerCaseKeys(response.headers)),
      encodedDataLength: response.encodedDataLength ?? 0
    });
    const apiRequest = apiRequests.get(requestId);
    if (apiRequest) apiRequest.status = response.status;
  });
  cdp.on("Network.loadingFinished", ({ requestId, encodedDataLength, timestamp }) => {
    const request = requests.get(requestId);
    if (request) request.encodedDataLength = encodedDataLength;
    const apiRequest = apiRequests.get(requestId);
    if (apiRequest) {
      apiRequest.settled = true;
      apiRequest.durationMs = (timestamp - apiRequest.startedAtMonotonic) * 1_000;
    }
  });
  cdp.on("Network.loadingFailed", ({ requestId, errorText, timestamp }) => {
    const apiRequest = apiRequests.get(requestId);
    if (apiRequest) {
      apiRequest.settled = true;
      apiRequest.failed = errorText;
      apiRequest.durationMs = (timestamp - apiRequest.startedAtMonotonic) * 1_000;
    }
  });

  const dashboardResponsePromise = page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/api/dashboard" && response.ok(),
    { timeout: 30_000 }
  );
  await page.goto(new URL(`/?barragan-perf=${index}-${cacheState}`, baseUrl).href, { waitUntil: "domcontentloaded" });
  const dashboardResponse = await dashboardResponsePromise;
  const dashboardBody = (await dashboardResponse.json()).dashboard;
  await page.locator("[data-barragan-dashboard-ready='true']").waitFor({ state: "attached", timeout: 30_000 });
  await page.waitForTimeout(0);
  const observed = await page.evaluate(() => {
    const marker = document.querySelector("[data-barragan-dashboard-ready='true']");
    const health = [...document.querySelectorAll("[aria-label='Barragan health'] strong")].map((node) => node.textContent?.trim() ?? "");
    return {
      readyAt: window.__barraganPerf.readyAt,
      timeOrigin: performance.timeOrigin,
      markerGeneratedAt: marker?.getAttribute("data-dashboard-generated-at") ?? null,
      health,
      bodyText: document.body.innerText,
      longTasks: window.__barraganPerf.longTasks,
      resources: performance.getEntriesByType("resource").map((entry) => ({
        name: entry.name, startTime: entry.startTime, duration: entry.duration, transferSize: entry.transferSize,
        encodedBodySize: entry.encodedBodySize, decodedBodySize: entry.decodedBodySize,
        responseStatus: entry.responseStatus
      }))
    };
  });
  const usableMs = observed.readyAt + validationProbeMs;
  if (!dashboardBody || observed.markerGeneratedAt !== dashboardBody.generatedAt) throw new Error("ready marker is not tied to the successful Dashboard generatedAt");
  if (dashboardBody.summary?.engagements !== expectedEngagements || dashboardBody.summary?.jobRuns !== expectedJobs) {
    throw new Error(`fixture cardinality mismatch: expected engagements=${expectedEngagements}, jobs=${expectedJobs}`);
  }
  if (observed.health.length < 4 || observed.health.some((value) => !value || value === "Loading")) throw new Error("ready marker appeared before nonloading health fields");
  for (const engagement of dashboardBody.engagementOverview?.active ?? []) {
    if (!observed.bodyText.includes(engagement.engagementName)) throw new Error(`ready marker appeared without engagement ${engagement.engagementName}`);
  }
  const readyAtWallMs = observed.timeOrigin + observed.readyAt;
  const preReadyApiResources = [...apiRequests.values()]
    .filter((request) => request.startedAtWallMs < readyAtWallMs)
    .map((request) => request.endpoint)
    .sort();
  const expectedPreReadyApiResources = ["/api/auth/session", "/api/dashboard"].sort();
  if (JSON.stringify(preReadyApiResources) !== JSON.stringify(expectedPreReadyApiResources)) {
    throw new Error(`usable-ready API resources must be exactly auth and Dashboard: ${preReadyApiResources.join(",")}`);
  }

  const postReadyDrainStartedAt = performance.now();
  await page.waitForLoadState("networkidle", { timeout: 30_000 });
  const postReadyDrainMs = performance.now() - postReadyDrainStartedAt;
  const postReadyApiRequests = [...apiRequests.values()]
    .filter((request) => request.startedAtWallMs >= readyAtWallMs)
    .sort((left, right) => left.endpoint.localeCompare(right.endpoint));
  const expectedPostReadyApiResources = [...auxiliaryEndpoints].sort();
  const observedPostReadyApiResources = postReadyApiRequests.map((request) => request.endpoint);
  if (JSON.stringify(observedPostReadyApiResources) !== JSON.stringify(expectedPostReadyApiResources)) {
    throw new Error(`post-ready API resources must be exactly the approved auxiliaries: ${observedPostReadyApiResources.join(",")}`);
  }
  const unsettledApiRequests = [...apiRequests.values()].filter((request) => !request.settled);
  if (unsettledApiRequests.length) {
    throw new Error(`startup API requests remained in flight after drain: ${unsettledApiRequests.map((request) => request.endpoint).join(",")}`);
  }
  const failedApiRequests = [...apiRequests.values()].filter((request) => request.failed || request.status < 200 || request.status >= 300);
  if (failedApiRequests.length) {
    throw new Error(`startup API requests failed: ${failedApiRequests.map((request) => `${request.endpoint}:${request.status ?? request.failed}`).join(",")}`);
  }
  const auxiliary = postReadyApiRequests.map((request) => {
    return {
      endpoint: request.endpoint,
      status: request.status,
      startTime: request.startedAtWallMs - observed.timeOrigin,
      durationMs: request.durationMs,
    };
  });
  const browserRequests = [...requests.entries()].map(([requestId, request]) => ({ ...request, requestHeaders: redactHeaders(requestHeaders.get(requestId) ?? {}) })).filter((request) => request.url.startsWith(baseUrl.origin));
  const requestList = [...validationProbes, ...browserRequests];
  const expectedAssets = [...new Set(expectedAssetUrls)];
  const assetEvidence = expectedAssets.map((asset) => requestList.find((request) => request.url === asset && (cacheState !== "validated" || request.validationProbe))).filter(Boolean);
  if (assetEvidence.length !== expectedAssets.length) throw new Error(`missing JS/CSS evidence: expected ${expectedAssets.length}, observed ${assetEvidence.length}`);
  const invalidValidatedAssets = cacheState === "validated"
    ? assetEvidence.filter((request) => request.status !== 304 || (!request.requestHeaders["if-none-match"] && !request.requestHeaders["if-modified-since"]))
    : [];
  if (invalidValidatedAssets.length) {
    const evidence = invalidValidatedAssets.map((request) => ({
      url: request.url,
      status: request.status,
      hasEtagValidator: Boolean(request.requestHeaders["if-none-match"]),
      hasModifiedValidator: Boolean(request.requestHeaders["if-modified-since"]),
      fromDiskCache: request.fromDiskCache,
      encodedDataLength: request.encodedDataLength,
    }));
    throw new Error(`every validated JS/CSS asset must carry a validator and return 304: ${JSON.stringify(evidence)}`);
  }
  if (cacheState === "cold" && assetEvidence.some((request) => request.status !== 200 || request.fromDiskCache || request.encodedDataLength <= 0)) {
    throw new Error("every cold JS/CSS asset must be a full status-200 network transfer");
  }
  if (cacheState === "warm" && assetEvidence.some((request) => request.status < 200 || request.status >= 300 || !(request.fromDiskCache || request.encodedDataLength === 0))) {
    throw new Error("every warm JS/CSS asset must have a successful response plus disk/memory cache or zero-transfer evidence");
  }
  await page.close();
  return {
    usableMs,
    validationProbeMs,
    usableReadyApiResources: preReadyApiResources,
    postReadyDrainMs,
    auxiliary,
    authenticationMs: resourceDuration(observed.resources, "/api/auth/session"),
    dashboardMs: resourceDuration(observed.resources, "/api/dashboard"),
    assetTransferBytes: requestList.filter((request) => request.url.includes("/assets/")).reduce((total, request) => total + request.encodedDataLength, 0),
    longTaskMs: observed.longTasks.reduce((total, task) => total + task.duration, 0),
    markerGeneratedAt: observed.markerGeneratedAt,
    requests: requestList,
    resources: observed.resources
  };
}

async function runValidationProbes(browserContext, validators) {
  return Promise.all(Object.entries(validators).map(async ([url, validator]) => {
    const requestHeaders = {
      "Cache-Control": "no-cache",
      ...(validator.etag ? { "If-None-Match": validator.etag } : {}),
      ...(validator.lastModified ? { "If-Modified-Since": validator.lastModified } : {}),
    };
    const response = await browserContext.request.get(url, {
      failOnStatusCode: false,
      headers: requestHeaders,
    });
    const body = await response.body();
    return {
      url,
      status: response.status(),
      mimeType: response.headers()["content-type"] ?? "",
      fromDiskCache: false,
      fromServiceWorker: false,
      headers: redactHeaders(lowerCaseKeys(response.headers())),
      encodedDataLength: body.byteLength,
      requestHeaders: redactHeaders(lowerCaseKeys(requestHeaders)),
      validationProbe: true,
    };
  }));
}

function resourceDuration(resources, pathname) {
  return resources.find((resource) => new URL(resource.name).pathname === pathname)?.duration ?? null;
}

function lowerCaseKeys(object) {
  return Object.fromEntries(Object.entries(object).map(([key, value]) => [key.toLowerCase(), String(value)]));
}

function redactHeaders(headers) {
  const redacted = { ...headers };
  for (const name of ["cookie", "set-cookie", "authorization", "x-csrf-token", "x-api-key"]) {
    if (name in redacted) redacted[name] = "<redacted>";
  }
  return redacted;
}

function nearestRank(values, percentile) {
  const sorted = values.filter(Number.isFinite).sort((left, right) => left - right);
  if (!sorted.length) return null;
  return sorted[Math.max(0, Math.ceil((percentile / 100) * sorted.length) - 1)];
}

function summarize(pairs) {
  const result = {};
  for (const state of ["cold", "validated", "warm"]) {
    result[state] = {};
    for (const metric of ["usableMs", "validationProbeMs", "postReadyDrainMs", "authenticationMs", "dashboardMs", "assetTransferBytes", "longTaskMs"]) {
      const values = pairs.map((pair) => pair[state][metric]);
      result[state][metric] = { p50: nearestRank(values, 50), p95: nearestRank(values, 95) };
    }
  }
  return result;
}

function environmentMetadata() {
  return {
    platform: process.platform,
    release: os.release(),
    architecture: os.arch(),
    cpuModel: os.cpus()[0]?.model ?? null,
    cpuCount: os.cpus().length,
    memoryBytes: os.totalmem(),
    nodeVersion: process.version
  };
}

function buildMetadata(assetUrls) {
  const revision = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repositoryRoot, encoding: "utf8" }).trim();
  const assets = assetUrls.map((url) => {
    const filename = path.basename(new URL(url).pathname);
    const localPath = path.join(frontendRoot, "dist", "assets", filename);
    try {
      return { filename, bytes: statSync(localPath).size };
    } catch {
      return { filename, bytes: null };
    }
  });
  return { revision, assets };
}
