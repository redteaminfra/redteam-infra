/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { StrictMode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthenticatedApp, permanentPasswordPolicyError } from "./AuthenticatedApp";
import { apiClient, DashboardInventory, rememberCsrfToken } from "../api/client";

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("AuthenticatedApp", () => {
  it("starts session and Dashboard together and renders prefetched Dashboard before auxiliaries settle", async () => {
    let resolveSession!: (response: Response) => void;
    let resolveDashboard!: (response: Response) => void;
    const requests: string[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      requests.push(path);
      if (path.endsWith("/api/auth/session")) return new Promise<Response>((resolve) => { resolveSession = resolve; });
      if (path.endsWith("/api/dashboard")) return new Promise<Response>((resolve) => { resolveDashboard = resolve; });
      if (path.endsWith("/api/templates") || path.endsWith("/api/engagements?scope=all")) return new Promise<Response>(() => undefined);
      return Promise.resolve(response({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<StrictMode><AuthenticatedApp /></StrictMode>);
    await waitFor(() => expect(requests.slice(0, 2)).toEqual(["/api/auth/session", "/api/dashboard"]));
    resolveDashboard(response({ dashboard: dashboardFixture("2026-08-04T16:00:00Z") }));
    await Promise.resolve();
    expect(screen.getByRole("heading", { name: "Opening Barragan" })).toBeInTheDocument();
    resolveSession(response(authenticatedSession()));

    await waitFor(() => expect(document.querySelector("[data-dashboard-generated-at='2026-08-04T16:00:00Z']")).not.toBeNull());
    expect(requests.filter((path) => path.endsWith("/api/dashboard"))).toHaveLength(1);
    expect(requests).toContain("/api/templates");
    expect(requests).toContain("/api/engagements?scope=all");
  });

  it.each([
    ["signed out", { authRequired: true, authenticated: false, user: null, mustChangePassword: false }, "Sign in to Barragan"],
    ["forced password change", { ...authenticatedSession(), mustChangePassword: true }, "Choose a permanent password"]
  ])("never exposes prefetched Dashboard data when %s", async (_label, session, heading) => {
    const dashboard = dashboardFixture("2026-08-04T16:01:00Z");
    dashboard.systemHealth.api.detail = "must remain private";
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/api/auth/session")) return Promise.resolve(response(session));
      if (path.endsWith("/api/dashboard")) return Promise.resolve(response({ dashboard }));
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<StrictMode><AuthenticatedApp /></StrictMode>);
    await screen.findByRole("heading", { name: heading });
    expect(document.querySelector("[data-barragan-dashboard-ready]")).toBeNull();
    expect(screen.queryByText("must remain private")).not.toBeInTheDocument();
  });

  it("falls back to App Dashboard loading when the parallel prefetch rejects", async () => {
    let dashboardCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/api/auth/session")) return Promise.resolve(response(authenticatedSession()));
      if (path.endsWith("/api/dashboard")) {
        dashboardCalls += 1;
        if (dashboardCalls === 1) return Promise.reject(new Error("prefetch unavailable"));
        return Promise.resolve(response({ dashboard: dashboardFixture("2026-08-04T16:02:00Z") }));
      }
      if (path.endsWith("/api/templates")) return Promise.resolve(response({ templates: [] }));
      if (path.endsWith("/api/engagements?scope=all")) return Promise.resolve(response({ engagements: [] }));
      return Promise.resolve(response({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<StrictMode><AuthenticatedApp /></StrictMode>);
    await waitFor(() => expect(document.querySelector("[data-dashboard-generated-at='2026-08-04T16:02:00Z']")).not.toBeNull());
    expect(dashboardCalls).toBe(2);
  });

  it("uses the prefetched Dashboard once and preserves future live refreshes", async () => {
    const requests: string[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      requests.push(path);
      if (path.endsWith("/api/auth/session")) return Promise.resolve(response(authenticatedSession()));
      if (path.endsWith("/api/dashboard")) return Promise.resolve(response({ dashboard: dashboardFixture("2026-08-04T16:03:00Z") }));
      if (path.endsWith("/api/dashboard?live=1")) return Promise.resolve(response({ dashboard: dashboardFixture("2026-08-04T16:04:00Z") }));
      if (path.endsWith("/api/templates")) return Promise.resolve(response({ templates: [] }));
      if (path.endsWith("/api/engagements?scope=all")) return Promise.resolve(response({ engagements: [] }));
      return Promise.resolve(response({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<StrictMode><AuthenticatedApp /></StrictMode>);
    await waitFor(() => expect(document.querySelector("[data-dashboard-generated-at='2026-08-04T16:03:00Z']")).not.toBeNull());
    expect(requests.filter((path) => path.endsWith("/api/dashboard"))).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Refresh Provider Inventory" }));
    await waitFor(() => expect(document.querySelector("[data-dashboard-generated-at='2026-08-04T16:04:00Z']")).not.toBeNull());
    expect(requests.filter((path) => path.includes("/api/dashboard"))).toHaveLength(2);
  });

  it("reuses the StrictMode bootstrap pair but never applies it after a genuine unmount", async () => {
    let resolveSession!: (response: Response) => void;
    let resolveDashboard!: (response: Response) => void;
    const requests: string[] = [];
    const unhandled = vi.fn();
    window.addEventListener("unhandledrejection", unhandled);
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      requests.push(path);
      if (path.endsWith("/api/auth/session")) return new Promise<Response>((resolve) => { resolveSession = resolve; });
      if (path.endsWith("/api/dashboard")) return new Promise<Response>((resolve) => { resolveDashboard = resolve; });
      return Promise.resolve(response({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<StrictMode><AuthenticatedApp /></StrictMode>);
    await waitFor(() => expect(requests).toEqual(["/api/auth/session", "/api/dashboard"]));
    view.unmount();
    resolveDashboard(response({ dashboard: dashboardFixture("2026-08-04T16:06:00Z") }));
    resolveSession(response(authenticatedSession()));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(document.querySelector(".app-shell")).toBeNull();
    expect(unhandled).not.toHaveBeenCalled();
    window.removeEventListener("unhandledrejection", unhandled);
  });

  it("counts permanent-password boundaries in Unicode code points", () => {
    expect(permanentPasswordPolicyError("123456789")).toBe("Password must be at least 10 characters.");
    expect(permanentPasswordPolicyError("1234567890")).toBe("");
    expect(permanentPasswordPolicyError("x".repeat(129))).toBe("Password must be at most 128 characters.");
    expect(permanentPasswordPolicyError("🔐".repeat(5))).toBe("Password must be at least 10 characters.");
    expect(permanentPasswordPolicyError("🔐".repeat(10))).toBe("");
  });

  it("sends CSRF for bodyless DELETE mutations", async () => {
    rememberCsrfToken("csrf-delete");
    const fetchMock = vi.fn(() => Promise.resolve(response({ engagement: {} })));
    vi.stubGlobal("fetch", fetchMock);
    await apiClient.deleteEngagement("eng-one");
    expect(fetchMock).toHaveBeenCalledWith("/api/engagements/eng-one", expect.objectContaining({
      method: "DELETE",
      headers: expect.objectContaining({ "X-Barragan-CSRF": "csrf-delete" })
    }));
  });

  it("signs in and requires a temporary password to be changed before loading Barragan", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.endsWith("/api/auth/session")) {
        return Promise.resolve(response({ authRequired: true, authenticated: false, user: null, mustChangePassword: false }));
      }
      if (path.endsWith("/api/dashboard")) {
        return Promise.resolve(response({ dashboard: dashboardFixture("2026-08-04T16:05:00Z") }));
      }
      if (path.endsWith("/api/auth/login")) {
        expect(JSON.parse(String(init?.body))).toEqual({ username: "example_operator_three", password: "temporary" });
        return Promise.resolve(response({
          authRequired: true,
          user: { id: "user-example_operator_three", username: "example_operator_three", displayName: "Example Operator", roles: ["administrator", "service_account"] },
          mustChangePassword: true,
          csrfToken: "csrf-test"
        }));
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<AuthenticatedApp />);
    await screen.findByRole("heading", { name: "Sign in to Barragan" });
    expect(document.querySelector(".auth-intro")).not.toBeInTheDocument();
    expect(screen.queryByText(/SSH tunnel/i)).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "example_operator_three" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "temporary" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByRole("heading", { name: "Choose a permanent password" });
    expect(window.localStorage.getItem("barragan.csrf-token")).toBe("csrf-test");
    expect(screen.getByLabelText("New password", { exact: true })).toHaveAttribute("minlength", "10");
    expect(screen.getByLabelText("Confirm new password")).toHaveAttribute("minlength", "10");
    expect(screen.getByText("Use 10–128 characters. Spaces and Unicode are welcome.")).toBeInTheDocument();
  });
});

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
}

function authenticatedSession() {
  return {
    authRequired: true,
    authenticated: true,
    user: { id: "user-example_operator_three", username: "example_operator_three", displayName: "Example Operator", roles: ["administrator", "service_account"] },
    mustChangePassword: false,
    csrfToken: "csrf-prefetch"
  };
}

function dashboardFixture(generatedAt: string): DashboardInventory {
  return {
    generatedAt,
    summary: { templates: 0, engagements: 0, activeEngagements: 0, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0 },
    engagementOverview: { active: [], recentlyEnded: [], recentlyArchived: [], windowDays: 30 },
    systemHealth: {
      api: { status: "ok", detail: "API ready" },
      database: { status: "ok", detail: "Database ready" },
      disk: { status: "ok", detail: "Disk ready" },
      providers: { status: "not checked", detail: "Providers not checked" }
    },
    inventory: [],
    orphanCandidates: [],
    reconciliation: { status: "local-records", detail: "Local fixture" }
  };
}
