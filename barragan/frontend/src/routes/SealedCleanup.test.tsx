/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { sealedCleanupFixture } from "../../e2e/fixtures/sealed-cleanup-progress";
import { App, selectedSealedCleanupState } from "./App";
import type { EngagementOperationsOverview, JobRunDetail } from "../api/client";

const fixture = (status: "queued" | "running" | "failed" | "succeeded" = "running") => {
  const value = sealedCleanupFixture(status);
  return { ...value, parent: value.parent as JobRunDetail, operations: value.operations as EngagementOperationsOverview };
};
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("Operations-selected sealed cleanup", () => {
  it.each([
    ["queued", "active"], ["running", "active"], ["failed", "recoverable"], ["succeeded", "complete"]
  ] as const)("recognizes %s separately as %s", (status, expected) => {
    const { parent, operations } = fixture(status);
    expect(selectedSealedCleanupState(parent, operations)).toBe(expected);
  });
  it.each([
    ["missing Operations", (_: any) => null],
    ["other engagement", (o: any) => ({ ...o, engagementId: "other" })],
    ["other parent", (o: any) => ({ ...o, teardownJob: { ...o.teardownJob, id: "other" } })],
    ["other core", (o: any) => ({ ...o, coreJob: { ...o.coreJob, id: "other" } })],
    ["missing core", (o: any) => ({ ...o, coreJob: null })],
    ["other action", (o: any) => ({ ...o, teardownJob: { ...o.teardownJob, action: "other" } })],
    ["other status", (o: any) => ({ ...o, teardownJob: { ...o.teardownJob, status: "failed" } })],
    ["absent", (o: any) => ({ ...o, teardownSelection: { state: "absent" } })],
    ["ambiguous", (o: any) => ({ ...o, teardownSelection: { state: "ambiguous" } })],
    ["unavailable", (o: any) => ({ ...o, teardownSelection: { state: "unavailable" } })],
    ["blocked", (o: any) => ({ ...o, teardownJob: { ...o.teardownJob, recoveryState: "blocked" } })],
    ["terminal mismatch", (o: any) => ({ ...o, teardownJob: { ...o.teardownJob, recoveryState: "complete" } })]
  ])("rejects %s", (_, change) => {
    const { parent, operations } = fixture();
    expect(selectedSealedCleanupState(parent, change(operations))).toBeNull();
  });
  it.each(["input marker", "queued marker", "scope", "hash", "snapshot", "target", "engagement", "schema"])("rejects inconsistent %s", (field) => {
    const { parent, operations } = fixture();
    const job = structuredClone(parent);
    if (field === "input marker") delete job.input.publishedInitialCleanupAuthority;
    if (field === "queued marker") delete job.events[0].data.publishedInitialCleanupAuthority;
    if (field === "scope") job.input.scopeSnapshot = null;
    if (field === "hash") job.input.publishedInitialCleanupAuthority.sha256 = "b".repeat(64);
    if (field === "snapshot") job.events[0].data.snapshotId = "other";
    if (field === "target") job.targetId = "other";
    if (field === "engagement") job.input.engagementId = "other";
    if (field === "schema") job.input.scopeSnapshot.publishedInitialCleanupSeal.schema = "unknown";
    expect(selectedSealedCleanupState(job, operations)).toBeNull();
  });
});

function routes(current: () => ReturnType<typeof fixture>) {
  const calls = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const value = current();
    const response = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } }));
    if (init?.method && init.method !== "GET") throw new Error("Reporting fixture forbids mutations");
    if (url.endsWith("/api/templates")) return response({ templates: [] });
    if (url.endsWith("/api/engagements?scope=all")) return response({ engagements: [value.engagement] });
    if (url.endsWith("/api/dashboard")) return response({ dashboard: null });
    if (url.endsWith(`/api/engagements/${value.engagement.id}/operations`)) return response({ operations: value.operations });
    if (url.endsWith(`/runs/${value.parent.id}/teardown`)) return response({ teardown: {
      snapshotId: "example-fresh-review", engagementId: value.engagement.id, engagementName: value.engagement.name,
      confirmationPhrase: "teardown-example-fixture", parentJobId: value.parent.id, orderedScope: []
    } });
    if (url.includes("/api/jobs?")) return response({ jobs: [{ id: value.parent.id, action: value.parent.action,
      status: value.parent.status, target: `engagement:${value.engagement.id}`, createdAt: "2026-10-29T00:00:00Z" }],
      pagination: { total: 1, limit: 50, offset: 0, hasMore: false } });
    if (url.endsWith(`/api/jobs/${value.parent.id}`)) return response({ job: value.parent });
    if (url.endsWith(`/runs/${value.parent.id}`)) return response({ job: value.parent });
    if (url.endsWith(`/runs/${value.core.id}`)) return response({ job: value.core });
    return response({});
  });
  vi.stubGlobal("fetch", calls);
  return calls;
}

it.each(["queued", "running", "failed"] as const)("loads exact %s sealed cleanup on fresh mount without a legacy target rejection", async (status) => {
  const calls = routes(() => fixture(status));
  const view = render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  expect(await screen.findByRole("heading", { name: status === "failed" ? "Recover Infrastructure Cleanup" : "Infrastructure teardown in progress" })).toBeInTheDocument();
  expect(screen.queryByText("Cleanup recovery unavailable")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Deploy New Chain" })).not.toBeInTheDocument();
  expect(calls.mock.calls.some(([, init]) => init?.method && init.method !== "GET")).toBe(false);
  view.unmount();
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  expect(await screen.findByRole("heading", { name: status === "failed" ? "Recover Infrastructure Cleanup" : "Infrastructure teardown in progress" })).toBeInTheDocument();
});

it("keeps sealed cleanup blocked when exact selection is missing", async () => {
  const value = fixture();
  value.operations.teardownSelection = { state: "ambiguous" };
  const calls = routes(() => value);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  expect(await screen.findByText("Cleanup recovery unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  expect(calls.mock.calls.some(([, init]) => init?.method && init.method !== "GET")).toBe(false);
});


it("retains the exact open console through terminal completion without exposing retry or deployment", async () => {
  let current = fixture();
  const calls = routes(() => current);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  await screen.findByRole("heading", { name: "Infrastructure teardown in progress" });
  fireEvent.click(screen.getByRole("button", { name: "Open Console" }));
  expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("engagement teardown queued");
  current = fixture("succeeded");
  await waitFor(() => expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("engagement lifecycle reconciled"), { timeout: 4000 });
  expect(await screen.findByRole("heading", { name: "Infrastructure Destroyed" })).toBeInTheDocument();
  expect(screen.queryByText("Cleanup recovery unavailable")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Deploy New Chain" })).not.toBeInTheDocument();
  expect(calls.mock.calls.some(([, init]) => init?.method && init.method !== "GET")).toBe(false);
});

it("never falls back to legacy recognition for a missing sealed marker or an unsealed former-listener target", async () => {
  const value = fixture();
  delete value.parent.input.publishedInitialCleanupAuthority;
  delete value.parent.events[0].data.publishedInitialCleanupAuthority;
  delete value.parent.input.scopeSnapshot.publishedInitialCleanupSeal;
  routes(() => value);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  expect(await screen.findByText("Cleanup recovery unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
});

it("does not let a late parent response for a previous engagement unlock the current selection", async () => {
  const old = fixture();
  const other = { ...old.engagement, id: "eng-other-example", name: "Example fixture: other engagement" };
  let release!: (response: Response) => void;
  const deferred = new Promise<Response>((resolve) => { release = resolve; });
  const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/templates")) return Promise.resolve(json({ templates: [] }));
    if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(json({ engagements: [old.engagement, other] }));
    if (url.endsWith(`/api/engagements/${old.engagement.id}/operations`)) return Promise.resolve(json({ operations: old.operations }));
    if (url.endsWith(`/api/engagements/${other.id}/operations`)) return Promise.resolve(json({ operations: { ...old.operations, engagementId: other.id, teardownSelection: { state: "ambiguous" } } }));
    if (url.endsWith(`/runs/${old.parent.id}`)) return deferred.then(() => json({ job: old.parent }));
    return Promise.resolve(json({}));
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/runs/${old.parent.id}`))).toBe(true));
  fireEvent.change(screen.getByRole("combobox", { name: "Active engagement" }), { target: { value: other.id } });
  await screen.findByText("Cleanup recovery unavailable");
  await act(async () => { release(json({ job: old.parent })); });
  expect(screen.getByText("Cleanup recovery unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: "Infrastructure teardown in progress" })).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole("combobox", { name: "Active engagement" }), { target: { value: old.engagement.id } });
  await waitFor(() => expect(screen.getByRole("combobox", { name: "Active engagement" })).toHaveValue(old.engagement.id));
  expect(await screen.findByRole("heading", { name: "Infrastructure teardown in progress" })).toBeInTheDocument();
});


it("reviews a failed selected parent afresh without submitting a cleanup mutation", async () => {
  const calls = routes(() => fixture("failed"));
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Infrastructure" }));
  const retry = await screen.findByRole("button", { name: "Retry Tear Down" });
  expect(retry).toBeEnabled();
  fireEvent.click(retry);
  expect(await screen.findByRole("group", { name: "Confirm tear down" })).toHaveTextContent("teardown-example-fixture");
  await waitFor(() => expect(calls.mock.calls.some(([url]) => String(url).endsWith("/teardown"))).toBe(true));
  expect(screen.getByRole("button", { name: "Confirm Tear Down" })).toBeDisabled();
  expect(calls.mock.calls.some(([, init]) => init?.method && init.method !== "GET")).toBe(false);
});

it("opens sealed job History as read-only navigation before loading exact engagement Operations", async () => {
  const value = fixture("failed");
  const calls = routes(() => value);
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Jobs", exact: true }));
  fireEvent.click(await screen.findByRole("button", { name: `Select job ${value.parent.id}` }));
  expect(screen.queryByRole("button", { name: "Resume Cleanup" })).not.toBeInTheDocument();
  fireEvent.click(await screen.findByRole("button", { name: "Open Engagement", exact: true }));
  expect(await screen.findByRole("heading", { name: "Recover Infrastructure Cleanup" })).toBeInTheDocument();
  expect(calls.mock.calls.some(([url]) => String(url).endsWith(`/api/engagements/${value.engagement.id}/operations`))).toBe(true);
  expect(calls.mock.calls.some(([, init]) => init?.method && init.method !== "GET")).toBe(false);
});
