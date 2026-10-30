/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { publishedTeardownFixture } from "../../e2e/fixtures/published-teardown-progress";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { StrictMode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App, buildDeploymentSteps, buildSketchSshConfigStanza, buildTeardownSteps, currentInfrastructureCommandActivity, dashboardResponseIsComplete, infrastructureCommandActivitySummary, infrastructureConsoleCurrentTask, infrastructureConsoleEventText, infrastructureWorkflowMode, jobConsoleText, mixedSketchPublicationPending, mixedZeroApplyProgressMessage, publishedTeardownTiming, outboundChannelConfigurationStepStatus, progressConsolePrimaryState, retainedSketchBootstrapEligible, sketchConsoleEventText, sketchLifecycleConsoleCopy } from "./App";

describe("mixed zero-Apply teardown progress", () => {
  const baseJob = {
      id: "job-mixed", action: "provider_keyed_mixed_zero_apply_cleanup",
      status: "queued", targetType: "engagement", targetId: "eng-test",
      requestedBy: "operator", input: { engagementId: "eng-test" },
      artifactRefs: [], events: []
  };
  it.each([
    ["core_destroy_preview", 0, "Review the exact core destroy plan"],
    ["core_destroy_apply", 1, "Apply the saved core destroy plan"],
    ["core_absence", 2, "Prove exact core resource absence"],
    ["public_negative", 3, "Verify former public SSH targets from Inspector"],
    ["inspector_retirement", 4, "Retire owned Inspector resources"],
    ["lifecycle_reconciliation", 5, null]
  ] as const)("maps backend phase %s after %i child receipts", (phase, completed, activeLabel) => {
    const job = { ...baseJob, phase, progress: { completed, total: 5 } };
    const steps = buildTeardownSteps(job, "running");
    expect(steps).toHaveLength(5);
    expect(steps.filter((step) => step.status === "done")).toHaveLength(completed);
    expect(steps.map((step) => step.label).join(" ")).not.toContain("outbound configuration");
    if (activeLabel) {
      expect(steps[completed].label).toBe(activeLabel);
      expect(steps[completed].status).toBe("wip");
    } else {
      expect(steps.every((step) => step.status === "done")).toBe(true);
    }
    expect(mixedZeroApplyProgressMessage(job)).toContain(`${completed}/5 phases complete`);
  });
});

describe("mixed interrupted teardown progress", () => {
  it.each([
    [["linode", "digitalocean"], "digitalocean_absence", "Verify digitalocean resources are absent"],
    [["digitalocean", "linode"], "linode_absence", "Verify linode resources are absent"]
  ] as const)("shows the reviewed provider order", (order, phase, label) => {
    const job = {
      id: "job-mixed-interrupted", action: "provider_keyed_mixed_interrupted_cleanup",
      status: "queued", targetType: "engagement", targetId: "eng-test",
      requestedBy: "operator", artifactRefs: [], events: [],
      input: { engagementId: "eng-test", coreJobId: "job-core",
        sourceSha256: "a".repeat(64),
        source: { ordered_providers: [...order], scopes: [
          { provider: "digitalocean", selector_retirement_pending: true }] } },
      phase, progress: { completed: 2, total: 9 }
    };
    const steps = buildTeardownSteps(job, "running");
    expect(steps).toHaveLength(9);
    expect(steps[2].label).toBe(label);
    expect(steps[2].status).toBe("wip");
    expect(mixedZeroApplyProgressMessage(job)).toContain("2/9 phases complete");
  });
});

describe("keyed publication readiness after reload", () => {
  afterEach(() => window.localStorage.removeItem("barragan.selectedEngagementId"));
  const engagement = { id: "eng-zy01", sketchStateSchema: "provider-keyed-v2" };
  const publishedRows = ["digitalocean", "linode"].flatMap((provider) => ["middle", "edge"].map((role) => ({
    chainId: `chain-${provider}`, hostname: `${role}-${provider}`, provider, role,
    publicIp: "192.0.2.10", region: "example", proxy: "proxy01", status: "deployed", burned: false, burnedNote: "",
    deploymentJobId: "job-provider-keyed-mixed-initial-pilot-001"
  })));
  const published = () => ({ ...operationsOverview(""), coreJob: operationsOverview("").activeJob, lifecycle: { state: "active", label: "Active", attentionRequired: false, terminal: false }, sketchInfrastructure: publishedRows });
  const pendingParent = { id: "job-provider-keyed-mixed-initial-example", action: "provider_keyed_mixed_initial",
    status: "running", createdAt: "2026-10-27T12:00:00Z", finishedAt: null, phase: "awaiting_mixed_host_proof" };

  it.each([
    ["loading", null, true],
    ["another engagement", { ...published(), engagementId: "eng-other" }, true],
    ["missing publication", { ...published(), sketchInfrastructure: [] }, true],
    ["only one provider", { ...published(), sketchInfrastructure: publishedRows.slice(0, 2) }, true],
    ["missing edge", { ...published(), sketchInfrastructure: publishedRows.filter((row) => row.provider !== "linode" || row.role !== "edge") }, true],
    ["pending chain records", { ...published(), sketchInfrastructure: publishedRows.map((row) => ({ ...row, status: "pending" })) }, true],
    ["unknown lifecycle", { ...published(), lifecycle: undefined }, true],
    ["running parent", { ...published(), mixedInitialJob: pendingParent }, true],
    ["queued parent", { ...published(), mixedInitialJob: { ...pendingParent, status: "queued" } }, true],
    ["missing core", { ...published(), coreJob: null }, true],
    ["running core", { ...published(), coreJob: { ...published().coreJob, status: "running" } }, true],
    ["old deployment generation", { ...published(), coreJob: { ...published().coreJob, id: "job-new-core" } }, true],
    ["missing publisher identity", { ...published(), sketchInfrastructure: publishedRows.map((row) => ({ ...row, deploymentJobId: undefined })) }, true],
    ["canonical publication", published(), false],
    ...["not_deployed", "tearing_down", "cleanup_required", "destroyed"].map((state) =>
      [state, { ...published(), lifecycle: { ...published().lifecycle, state }, mixedInitialJob: pendingParent }, false])
  ])("uses durable %s with no remembered plan", (_label, operations, expected) => {
    expect(mixedSketchPublicationPending(null, operations as never, engagement)).toBe(expected);
  });

  it("does not apply keyed gates to split-v1", () => {
    expect(mixedSketchPublicationPending(null, { ...published(), mixedInitialJob: pendingParent } as never,
      { ...engagement, sketchStateSchema: "split-v1" })).toBe(false);
  });

  it("fresh mount keeps pending keyed cards locked and refreshes through publication without writes", async () => {
    let operations = { ...published(), sketchInfrastructure: [] as typeof publishedRows, mixedInitialJob: pendingParent as typeof pendingParent | null };
    const pendingChain = sketchChainRecord();
    const fetchMock = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ sketchStateSchema: "provider-keyed-v2" })] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [pendingChain] }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/runs/job-pilot-001")) return Promise.resolve(jsonResponse({ job: pilotRunJob("eng-zy01") }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByText(/Both provider plans were applied/)).toBeInTheDocument();
    expect(screen.getByText("host verification pending")).toBeInTheDocument();
    for (const name of ["Deploy New Chain", "Retry Bootstrap", "Cancel", "Retire Final Edge", "Add Replacement Edge", "Tear Down Chain", "Stop Nodes", "Mark Burned"]) {
      expect(screen.queryByRole("button", { name, exact: true })).not.toBeInTheDocument();
    }
    expect(screen.queryByRole("button", { name: /Add proxy.* Chain/ })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/live middle provider/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Overview", exact: true }));
    const notes = await screen.findByLabelText("Housekeeping Items");
    fireEvent.change(notes, { target: { value: "Unsaved operator note" } });
    const pendingCalls = fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/operations")).length;
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/operations")).length).toBeGreaterThan(pendingCalls), { timeout: 5000 });
    expect(notes).toHaveValue("Unsaved operator note");
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure", exact: true }));
    expect(await screen.findByText(/Both provider plans were applied/)).toBeInTheDocument();
    operations = { ...published(), mixedInitialJob: null };
    await waitFor(() => expect(screen.queryByText(/Both provider plans were applied/)).not.toBeInTheDocument(), { timeout: 5000 });
    const calls = fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/operations")).length;
    await new Promise((resolve) => setTimeout(resolve, 3200));
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/operations"))).toHaveLength(calls);
    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === "POST")).toBe(false);
  }, 20000);
});

describe("infrastructure recovery state", () => {
  it("does not present a retained mixed plan as deploying after teardown", () => {
    const base = corePlanReviewFixture();
    const plan = corePlanReviewFixture({
      status: "applied",
      reviewedConfiguration: {
        ...base.reviewedConfiguration,
        sketchAuthorization: { kind: "bounded-mixed-post-core-v1" }
      }
    }) as never;
    const baseOperations = emptyOperationsOverview("");
    const lifecycle = baseOperations.lifecycle!;
    expect(mixedSketchPublicationPending(plan, {
      ...baseOperations, lifecycle: { ...lifecycle, state: "active" }, sketchInfrastructure: []
    } as never)).toBe(true);
    for (const state of ["tearing_down", "cleanup_required", "destroyed"] as const) {
      expect(mixedSketchPublicationPending(plan, {
        ...baseOperations, lifecycle: { ...lifecycle, state }, sketchInfrastructure: []
      } as never)).toBe(false);
    }
  });

  it.each([
    ["exact teardown recovery", { lifecycleState: "cleanup_required", teardownJobPresent: true, teardownRecoveryJobAvailable: true, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false }, "teardown_recovery"],
    ["blocked teardown with stale core", { lifecycleState: "cleanup_required", teardownJobPresent: true, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: true, activeCoreInfrastructure: true }, "blocked"],
    ["tearing down without a parent", { lifecycleState: "tearing_down", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false }, "blocked"],
    ["retained bootstrap recovery", { lifecycleState: "cleanup_required", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: true, activeCoreInfrastructure: true }, "running"],
    ["legacy failed chain cleanup with active core", { lifecycleState: "cleanup_required", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, legacyChainCleanupAvailable: true, activeCoreInfrastructure: true }, "running"],
    ["cleanup with stale core but no retained retry", { lifecycleState: "cleanup_required", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: true }, "blocked"],
    ["destroyed with stale deployment and recovery evidence", { lifecycleState: "destroyed", teardownJobPresent: true, teardownRecoveryJobAvailable: true, retainedBootstrapRecoveryAvailable: true, activeCoreInfrastructure: true }, "historical"],
    ["destroyed with no retained hosts", { lifecycleState: "destroyed", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false }, "historical"],
    ["new active generation after historical teardown", { lifecycleState: "active", teardownJobPresent: true, teardownJobComplete: true, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: true }, "running"],
    ["new deploying generation after historical teardown", { lifecycleState: "deploying", teardownJobPresent: true, teardownJobComplete: true, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false, currentCoreDeploymentLoaded: true }, "deploying"],
    ["ordinary active core", { lifecycleState: "active", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: true }, "running"],
    ["deploying before core inventory appears", { lifecycleState: "deploying", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false, currentCoreDeploymentLoaded: true }, "deploying"],
    ["deploying while job detail loads", { lifecycleState: "deploying", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false, currentCoreDeploymentLoaded: false }, "loading"],
    ["Sketch deploying after core is available", { lifecycleState: "deploying", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: true, currentCoreDeploymentLoaded: false }, "running"],
    ["deploying with teardown parent", { lifecycleState: "deploying", teardownJobPresent: true, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false, currentCoreDeploymentLoaded: true }, "blocked"],
    ["zero-resource cleanup", { lifecycleState: "cleanup_required", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false }, "blocked"],
    ["clean fresh deployment", { lifecycleState: "not_deployed", teardownJobPresent: false, teardownRecoveryJobAvailable: false, retainedBootstrapRecoveryAvailable: false, activeCoreInfrastructure: false }, "fresh"]
  ])("selects %s", (_label, input, expected) => {
    expect(infrastructureWorkflowMode({ operationsReady: true, ...input })).toBe(expected);
  });

  it.each([
    ["idle", false, "loading"],
    ["loading", false, "loading"],
    ["error", true, "unavailable"]
  ] as const)("stays loading or unavailable while Operations is %s", (_status, operationsFailed, expected) => {
    expect(infrastructureWorkflowMode({
      operationsReady: false,
      operationsFailed,
      lifecycleState: "not_deployed",
      teardownJobPresent: false,
      teardownRecoveryJobAvailable: false,
      retainedBootstrapRecoveryAvailable: false,
      activeCoreInfrastructure: false
    })).toBe(expected);
  });

  it("requires a failed chain, canonical parent job ID, and retained nodes", () => {
    const eligible = { status: "failed", deployJobId: "job-existing", nodes: [{}] };
    const failedBootstrap = failedBootstrapJob("job-existing", "chain-existing");
    expect(retainedSketchBootstrapEligible(eligible, failedBootstrap)).toBe(true);
    expect(retainedSketchBootstrapEligible({ ...eligible, status: "deploying" }, failedBootstrap)).toBe(false);
    expect(retainedSketchBootstrapEligible({ ...eligible, deployJobId: "" }, failedBootstrap)).toBe(false);
    expect(retainedSketchBootstrapEligible({ ...eligible, deployJobId: " job-existing" }, failedBootstrap)).toBe(false);
    expect(retainedSketchBootstrapEligible({ ...eligible, nodes: [] }, failedBootstrap)).toBe(false);
    expect(retainedSketchBootstrapEligible(eligible, null)).toBe(false);
    expect(retainedSketchBootstrapEligible(eligible, { ...failedBootstrap, status: "succeeded" })).toBe(false);
    expect(retainedSketchBootstrapEligible(eligible, { ...failedBootstrap, events: [] })).toBe(false);
    expect(retainedSketchBootstrapEligible(eligible, {
      ...failedBootstrap,
      events: [{ sequence: 1, level: "error", message: "bootstrap", data: { bootstrap: "starting" } }]
    })).toBe(false);
  });
});

describe("sketch lifecycle console copy", () => {
  it("labels a retained-middle replacement from the durable parent action", () => {
    expect(sketchLifecycleConsoleCopy({
      id: "job-replace",
      action: "sketch_edge_replace",
      status: "running",
      targetType: "engagement",
      targetId: "eng-test",
      requestedBy: "operator",
      input: { edgeTransition: "replace" },
      artifactRefs: [],
      events: []
    })).toEqual({
      title: "Sketch edge replacement progress",
      emptyText: "Starting retained-middle edge replacement."
    });
  });
});

describe("infrastructure command activity", () => {
  const now = Date.parse("2026-07-31T12:02:00Z");
  const runningJob = (observedAt: string, completed = false) => ({
    id: "job-progress",
    action: "pilot_standard_rti",
    status: "running",
    targetType: "engagement",
    targetId: "eng-test",
    requestedBy: "operator",
    input: {},
    artifactRefs: [],
    events: [
      {
        sequence: 1,
        level: "info",
        message: "infrastructure command started",
        data: {
          eventKind: "command_started",
          step: "ansible_capabilities",
          phase: "Apply selected RTI capabilities",
          startedAt: "2026-07-31T12:00:00Z",
          observedAt: "2026-07-31T12:00:00Z"
        }
      },
      {
        sequence: 2,
        level: "info",
        message: "Ansible task progress",
        data: {
          eventKind: "ansible_task",
          step: "ansible_capabilities",
          phase: "Apply selected RTI capabilities",
          startedAt: "2026-07-31T12:00:00Z",
          observedAt,
          task: "Install baseline RTI tools"
        }
      },
      ...(completed ? [{
        sequence: 3,
        level: "info",
        message: "Ansible selected capabilities apply completed",
        data: { eventKind: "command_completed", step: "ansible_capabilities", status: "succeeded" }
      }] : [])
    ]
  });

  it("distinguishes fresh work, stale activity, and completion from persisted events", () => {
    const working = currentInfrastructureCommandActivity(runningJob("2026-07-31T12:01:50Z"), now);
    expect(working?.state).toBe("working");
    expect(infrastructureCommandActivitySummary(working!)).toContain("Working — Apply selected RTI capabilities");
    expect(infrastructureCommandActivitySummary(working!)).toContain("Install baseline RTI tools");

    const stalled = currentInfrastructureCommandActivity(runningJob("2026-07-31T12:00:29Z"), now);
    expect(stalled?.state).toBe("possibly_stalled");
    expect(infrastructureCommandActivitySummary(stalled!)).toContain("Possibly stalled");

    expect(currentInfrastructureCommandActivity(runningJob("2026-07-31T12:01:50Z", true), now)).toBeNull();
  });

  it("prefers live recognized Ansible activity over the broader deployment step", () => {
    const activity = currentInfrastructureCommandActivity(runningJob("2026-07-31T12:01:50Z"), now);

    expect(infrastructureConsoleCurrentTask(activity, "Configure RTI base layout")).toBe("Install baseline RTI tools");
    expect(infrastructureConsoleCurrentTask(null, "Configure RTI base layout")).toBe("Configure RTI base layout");
  });

  it("derives running and terminal console headings from durable job state", () => {
    const running = runningJob("2026-07-31T12:01:50Z");
    expect(progressConsolePrimaryState(running, "Deployment is running.", "Install baseline RTI tools")).toEqual({
      label: "Current task",
      text: "Install baseline RTI tools"
    });

    expect(progressConsolePrimaryState({ ...running, status: "succeeded" }, "Waiting for job activity", "Waiting for job activity")).toEqual({
      label: "Outcome",
      text: "Completed successfully."
    });

    const failed = {
      ...running,
      status: "failed",
      events: [
        ...running.events,
        { sequence: 3, level: "error", message: "Current attempt could not verify Inspector cleanup", data: {} }
      ]
    };
    expect(progressConsolePrimaryState(failed, "Cleanup is running.", "Verify cleanup")).toEqual({
      label: "Current failure",
      text: "Current attempt could not verify Inspector cleanup"
    });
  });

  it("separates current retry events from prior attempt history in every shared job console", () => {
    const retried = {
      ...runningJob("2026-07-31T12:01:50Z"),
      status: "running",
      events: [
        { sequence: 1, level: "error", message: "prior attempt failed", data: {} },
        { sequence: 2, level: "info", message: "engagement teardown retry queued", data: {} },
        { sequence: 3, level: "info", message: "Inspector teardown preflight started", data: {} }
      ]
    };

    const rendered = jobConsoleText(retried, "No events.");
    expect(rendered).toContain("current attempt\n2. INFO engagement teardown retry queued");
    expect(rendered).toContain("3. INFO Inspector teardown preflight started");
    expect(rendered).toContain("prior attempt history\n1. ERROR prior attempt failed");
    expect(rendered.indexOf("current attempt")).toBeLessThan(rendered.indexOf("prior attempt history"));
  });

  it("renders durable completion timing when the backend records it", () => {
    expect(infrastructureConsoleEventText({
      sequence: 4,
      level: "info",
      message: "Terraform apply completed",
      data: { eventKind: "command_completed", step: "terraform_apply", status: "succeeded", elapsedSeconds: 125 }
    })).toBe("Terraform created the core OCI infrastructure in 2m 5s (succeeded).");
    expect(infrastructureConsoleEventText({
      sequence: 5,
      level: "info",
      message: "Ansible bootstrap validation completed",
      data: { eventKind: "command_completed", step: "ansible_bootstrap", status: "succeeded" }
    })).toBe("Ansible configured the base RTI layout (succeeded).");
  });

  it("renders durable sketch Terraform timing when the provider records it", () => {
    expect(sketchConsoleEventText({
      sequence: 7,
      level: "info",
      message: "terraform apply completed",
      data: { phase: "apply", elapsedSeconds: 104.159 }
    })).toBe("Terraform provisioned the sketch infrastructure in 1m 44s.");
  });
});

describe("core deployment console boundaries", () => {
  it("does not mark a completed core job as active because its separate sketch job is running", () => {
    const coreJob = {
      ...pilotRunJob("eng-zy01"),
      input: {
        ...pilotRunJob("eng-zy01").input,
        postCoreSketchContinuationEligible: true
      }
    };
    const steps = buildDeploymentSteps(
      pilotReadiness(),
      "ready",
      null,
      coreJob,
      false,
      {
        sketchChain: {
          id: "proxy01-sea-01",
          assignedProxy: "proxy01",
          middleProvider: "linode",
          middleRegion: "us-sea",
          edgeProvider: "linode",
          edgeRegion: "us-sea",
          edges: []
        } as never,
        sketchJob: null,
        sketchRunStatus: "running",
        outboundChannels: []
      }
    );

    expect(steps.find((step) => step.id === "inspection")?.status).toBe("done");
    expect(steps.some((step) => step.id === "sketch-provision" && step.status === "wip")).toBe(false);
  });
});

describe("operator sketch SSH stanzas", () => {
  it("uses the administration account and engagement-qualified proxy aliases", () => {
    const deployed = operationsWithDeployedSketch([]);
    const operations = {
      ...deployed,
      sketchInfrastructure: deployed.sketchInfrastructure.map((node) => ({
        ...node,
        proxy: node.proxy.startsWith("proxy02") ? "proxy02" : "proxy01"
      }))
    };

    const stanzas = buildSketchSshConfigStanza(operations, sketchKey("SHA256:operator-key"));

    expect(stanzas).toContain("Host middle01-zy01\n    HostName 198.51.100.20\n    User user");
    expect(stanzas).toContain("ProxyJump proxy01-zy01");
    expect(stanzas).toContain("ProxyJump proxy01-zy01,middle01-zy01");
    expect(stanzas).toContain("ProxyJump proxy02-zy01");
    expect(stanzas).toContain("ProxyJump proxy02-zy01,middle02-zy01");
    expect(stanzas).not.toContain("User sketchssh");
    expect(stanzas).not.toContain("ProxyJump proxy01\n");
    expect(stanzas).not.toContain("ProxyJump proxy02\n");
  });
});

describe("engagement teardown progress", () => {
  const job = (messages: string[]) => ({
    id: "job-engagement-teardown-core",
    action: "engagement_comprehensive_teardown",
    status: "running",
    targetType: "engagement",
    targetId: "eng-test",
    requestedBy: "example_operator_three",
    input: {},
    artifactRefs: [],
    events: messages.map((message, index) => ({ sequence: index + 1, level: "info", message, data: {} }))
  });

  it("shows Inspector preflight before destructive cleanup", () => {
    const steps = buildTeardownSteps(
      job(["engagement teardown retry queued", "Inspector teardown preflight started"]),
      "running"
    );

    expect(steps.find((step) => step.id === "inspector-preflight")?.status).toBe("wip");
    expect(steps.find((step) => step.id === "inspector-preflight")?.active).toBe(true);
    expect(steps.find((step) => step.id === "sketch-cleanup")?.status).toBe("pending");
  });

  it("keeps destructive cleanup pending when Inspector preflight fails", () => {
    const steps = buildTeardownSteps(
      job([
        "engagement teardown queued",
        "Inspector teardown preflight started",
        "engagement teardown requires cleanup"
      ]),
      "idle"
    );

    expect(steps.find((step) => step.id === "inspector-preflight")?.status).toBe("failed");
    expect(steps.find((step) => step.id === "sketch-cleanup")?.status).toBe("pending");
  });

  it("keeps sketch cleanup active until the core gate actually opens", () => {
    const steps = buildTeardownSteps(
      job(["engagement teardown queued", "engagement sketch cleanup started"]),
      "running"
    );

    expect(steps.find((step) => step.id === "sketch-cleanup")?.status).toBe("wip");
    expect(steps.find((step) => step.id === "sketch-cleanup")?.active).toBe(true);
    expect(steps.find((step) => step.id === "core-cleanup")?.status).toBe("pending");
  });

  it("advances to core only after all sketch cleanup has crossed its gate", () => {
    const steps = buildTeardownSteps(
      job([
        "engagement teardown queued",
        "engagement sketch cleanup started",
        "core and Inspector cleanup started"
      ]),
      "running"
    );

    expect(steps.find((step) => step.id === "sketch-cleanup")?.status).toBe("done");
    expect(steps.find((step) => step.id === "core-cleanup")?.status).toBe("wip");
    expect(steps.find((step) => step.id === "core-cleanup")?.active).toBe(true);
  });

  it("uses only the latest retry attempt for terminal teardown progress", () => {
    const retriedJob = {
      ...job([]),
      status: "succeeded",
      events: [
        { sequence: 1, level: "info", message: "engagement teardown queued", data: {} },
        { sequence: 2, level: "info", message: "Inspector teardown preflight started", data: {} },
        { sequence: 3, level: "error", message: "engagement teardown requires cleanup", data: {} },
        { sequence: 4, level: "info", message: "engagement teardown retry queued", data: {} },
        { sequence: 5, level: "info", message: "Inspector teardown preflight started", data: {} },
        { sequence: 6, level: "info", message: "Inspector teardown preflight completed", data: {} },
        { sequence: 7, level: "info", message: "engagement sketch cleanup started", data: {} },
        { sequence: 8, level: "info", message: "core and Inspector cleanup started", data: {} },
        { sequence: 9, level: "info", message: "Inspector teardown verification completed", data: {} },
        { sequence: 10, level: "info", message: "Inspector cleanup completed", data: {} },
        { sequence: 11, level: "info", message: "engagement lifecycle reconciled", data: {} }
      ]
    };
    const steps = buildTeardownSteps(retriedJob, "idle");

    expect(steps.every((step) => step.status === "done")).toBe(true);
    expect(steps.some((step) => step.active || step.status === "failed" || step.status === "wip")).toBe(false);
  });
});

describe("App", () => {
  it("renders Dashboard readiness before starting and awaiting auxiliary bootstrap", async () => {
    const requests: string[] = [];
    let resolveDashboard!: (response: Response) => void;
    let resolveTemplates!: (response: Response) => void;
    let resolveEngagements!: (response: Response) => void;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      requests.push(url);
      if (url.endsWith("/api/dashboard")) return new Promise<Response>((resolve) => { resolveDashboard = resolve; });
      if (url.endsWith("/api/templates")) return new Promise<Response>((resolve) => { resolveTemplates = resolve; });
      if (url.endsWith("/api/engagements?scope=all")) return new Promise<Response>((resolve) => { resolveEngagements = resolve; });
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    const { container } = render(<StrictMode><App /></StrictMode>);
    await waitFor(() => expect(requests).toEqual(["/api/dashboard"]));

    const dashboard = emptyDashboardFixture();
    dashboard.generatedAt = "2026-08-04T15:00:00Z";
    dashboard.systemHealth.api.detail = "Dashboard won the startup path.";
    resolveDashboard(jsonResponse({ dashboard }));

    await waitFor(() => expect(container.querySelector("[data-dashboard-generated-at='2026-08-04T15:00:00Z']")).not.toBeNull());
    expect(screen.getByLabelText("Barragan health")).toHaveTextContent("Dashboard won the startup path.");
    await waitFor(() => expect(requests).toEqual(["/api/dashboard", "/api/templates", "/api/engagements?scope=all"]));

    resolveTemplates(jsonResponse({ templates: [] }));
    resolveEngagements(jsonResponse({ engagements: [] }));
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    expect(requests.filter((url) => url.endsWith("/api/dashboard"))).toHaveLength(1);
  });

  it("starts auxiliary bootstrap when navigation leaves a pending initial Dashboard", async () => {
    let resolveDashboard!: (response: Response) => void;
    const requests: string[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      requests.push(url);
      if (url.endsWith("/api/dashboard")) return new Promise<Response>((resolve) => { resolveDashboard = resolve; });
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<StrictMode><App /></StrictMode>);
    await waitFor(() => expect(requests).toEqual(["/api/dashboard"]));
    fireEvent.click(screen.getByRole("button", { name: "Engagements" }));
    await waitFor(() => expect(requests).toContain("/api/templates"));
    expect(requests).toContain("/api/engagements?scope=all");
    fireEvent.click(screen.getByRole("button", { name: "Dashboard" }));
    expect(requests.filter((url) => url.endsWith("/api/dashboard"))).toHaveLength(1);
    resolveDashboard(jsonResponse({ dashboard: emptyDashboardFixture() }));
    await waitFor(() => expect(document.querySelector("[data-barragan-dashboard-ready]")).not.toBeNull());
    expect(requests.filter((url) => url.endsWith("/api/dashboard"))).toHaveLength(1);
  });

  it("ignores auxiliary bootstrap completion after App unmounts", async () => {
    let resolveTemplates!: (response: Response) => void;
    let resolveEngagements!: (response: Response) => void;
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return new Promise<Response>((resolve) => { resolveTemplates = resolve; });
      if (url.endsWith("/api/engagements?scope=all")) return new Promise<Response>((resolve) => { resolveEngagements = resolve; });
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<App />);
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/api/templates"))).toBe(true));
    view.unmount();
    resolveTemplates(jsonResponse({ templates: [] }));
    resolveEngagements(jsonResponse({ engagements: [engagementSummary()] }));
    await Promise.resolve();
    await Promise.resolve();
    expect(consoleError).not.toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it("handles auxiliary bootstrap rejection after unmount without an unhandled rejection", async () => {
    let rejectTemplates!: (error: Error) => void;
    const unhandled = vi.fn();
    window.addEventListener("unhandledrejection", unhandled);
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return new Promise<Response>((_resolve, reject) => { rejectTemplates = reject; });
      if (url.endsWith("/api/engagements?scope=all")) return new Promise<Response>(() => undefined);
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    const view = render(<App />);
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/api/templates"))).toBe(true));
    view.unmount();
    rejectTemplates(new Error("auxiliary bootstrap failed after unmount"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(unhandled).not.toHaveBeenCalled();
    expect(document.querySelector(".app-shell")).toBeNull();
    window.removeEventListener("unhandledrejection", unhandled);
  });

  it("does not fetch provider catalogs during the initial Dashboard load", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/provider-catalog/"))).toBe(false);
  });

  it("loads the filtered provider catalog once on Infrastructure and gates catalog-backed controls", async () => {
    const catalogResolvers = new Map<string, (response: Response) => void>();
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Baseline", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.includes("/api/provider-catalog/sketch?provider=") && !url.includes("includeBlocked")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return new Promise<Response>((resolve) => catalogResolvers.set(provider, resolve));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));

    const template = await screen.findByLabelText("Infrastructure template");
    expect(template).toBeDisabled();
    expect(screen.getByRole("button", { name: "Prepare Infrastructure Plan" })).toBeDisabled();
    await waitFor(() => expect(catalogResolvers.size).toBe(2));
    catalogResolvers.get("linode")!(jsonResponse({ catalog: providerCatalog("linode") }));
    catalogResolvers.get("digitalocean")!(jsonResponse({ catalog: providerCatalog("digitalocean") }));
    await waitFor(() => expect(template).toBeEnabled());

    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByLabelText("Infrastructure template")).toBeEnabled());
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("/api/provider-catalog/sketch?provider=") && !String(input).includes("includeBlocked"))).toHaveLength(2);
  });

  it("preserves a catalog-backed single-edge size through one/two/one editing and the prepared request", async () => {
    const catalogResolvers = new Map<string, (response: Response) => void>();
    const infrastructureBodies: Array<Record<string, unknown>> = [];
    const selectedEngagement = engagementSummary({ templateId: "standard-rti" });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Baseline", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [selectedEngagement] }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.includes("/api/provider-catalog/sketch?provider=") && !url.includes("includeBlocked")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return new Promise<Response>((resolve) => catalogResolvers.set(provider, resolve));
      }
      if (url.endsWith("/api/engagements/eng-zy01/infrastructure") && init?.method === "POST") {
        const body = JSON.parse(String(init.body));
        infrastructureBodies.push(body);
        return Promise.resolve(jsonResponse({ engagement: { ...selectedEngagement, inputParameters: body.inputParameters } }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/revisions") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ revision: { id: "rev-single-edge", engagementId: "eng-zy01", revisionNumber: 1, status: "compiled", templateId: "standard-rti", inputParameters: infrastructureBodies[0].inputParameters, resolvedTopology: {}, runIntent: [], validationGates: validationGates() } }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(catalogResolvers.size).toBe(2));
    const edgeCount = screen.getByLabelText("proxy01-chain-1 edge nodes");
    expect(edgeCount).toBeDisabled();
    fireEvent.change(edgeCount, { target: { value: "1" } });
    fireEvent.click(screen.getAllByText("Advanced sketch settings")[0]);
    expect(screen.getByLabelText("proxy01-chain-1 edge size")).toBeDisabled();

    const linodeCatalog = providerCatalog("linode");
    catalogResolvers.get("linode")!(jsonResponse({
      catalog: {
        ...linodeCatalog,
        sizes: [
          ...linodeCatalog.sizes,
          { id: "shared-small", label: "Shared small", vcpus: 1, memoryMb: 768, diskGb: 20, priceMonthly: 5, available: true, regions: [] }
        ]
      }
    }));
    const digitalOceanCatalog = providerCatalog("digitalocean");
    catalogResolvers.get("digitalocean")!(jsonResponse({
      catalog: {
        ...digitalOceanCatalog,
        regions: [...digitalOceanCatalog.regions, { id: "nyc3", label: "New York 3", available: true }],
        sizes: [
          ...digitalOceanCatalog.sizes,
          { id: "shared-small", label: "Shared small", vcpus: 1, memoryMb: 768, diskGb: 20, priceMonthly: 5, available: true, regions: ["sfo3", "nyc3"] },
          { id: "s-1vcpu-512mb-10gb", label: "Basic 1 vCPU / 512 MB", vcpus: 1, memoryMb: 512, diskGb: 10, priceMonthly: 4, available: true, regions: ["sfo3", "nyc3"] }
        ],
        regionPolicy: { allowedRegions: ["sfo3", "nyc3"], includeBlocked: false }
      }
    }));
    await waitFor(() => expect(screen.getByLabelText("proxy01-chain-1 edge size")).toBeEnabled());

    const sharedEdgeSize = screen.getByLabelText("proxy01-chain-1 edge size");
    expect(sharedEdgeSize).toHaveValue("s-1vcpu-1gb");
    const defaultEdgeProvider = screen.getByLabelText("proxy01-chain-1 edge provider");
    fireEvent.change(sharedEdgeSize, { target: { value: "shared-small" } });
    fireEvent.change(defaultEdgeProvider, { target: { value: "linode" } });
    expect(sharedEdgeSize).toHaveValue("shared-small");
    fireEvent.change(sharedEdgeSize, { target: { value: "g6-standard-1" } });
    fireEvent.change(defaultEdgeProvider, { target: { value: "digitalocean" } });
    expect(sharedEdgeSize).toHaveValue("s-1vcpu-1gb");
    fireEvent.change(sharedEdgeSize, { target: { value: "s-1vcpu-512mb-10gb" } });
    expect(sharedEdgeSize).toHaveValue("s-1vcpu-512mb-10gb");
    const edgeRegion = screen.getByLabelText("proxy01-chain-1 default edge region");
    fireEvent.change(edgeRegion, { target: { value: "nyc3" } });
    expect(sharedEdgeSize).toHaveValue("s-1vcpu-512mb-10gb");
    fireEvent.change(edgeRegion, { target: { value: "sfo3" } });

    fireEvent.change(edgeCount, { target: { value: "2" } });
    expect(screen.queryByLabelText("proxy01-chain-1 edge size")).not.toBeInTheDocument();
    expect(screen.getByLabelText("proxy01-chain-1 edge 01 size")).toHaveValue("s-1vcpu-512mb-10gb");
    fireEvent.change(defaultEdgeProvider, { target: { value: "linode" } });
    expect(screen.getByLabelText("proxy01-chain-1 edge 01 size")).toHaveValue("g6-nanode-1");
    expect(screen.getByLabelText("proxy01-chain-1 edge 02 size")).toHaveValue("g6-nanode-1");
    fireEvent.change(edgeCount, { target: { value: "1" } });
    expect(screen.getByLabelText("proxy01-chain-1 edge size")).toHaveValue("g6-nanode-1");
    fireEvent.change(defaultEdgeProvider, { target: { value: "digitalocean" } });
    expect(screen.getByLabelText("proxy01-chain-1 edge size")).toHaveValue("s-1vcpu-1gb");
    fireEvent.change(screen.getByLabelText("proxy01-chain-1 edge size"), { target: { value: "s-1vcpu-512mb-10gb" } });

    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));
    await waitFor(() => expect(infrastructureBodies).toHaveLength(1));
    const preparedChain = (infrastructureBodies[0].inputParameters as { sketchChains: Array<Record<string, unknown>> }).sketchChains[0];
    expect(preparedChain).toMatchObject({
      edgeProvider: "digitalocean",
      edgeRegion: "sfo3",
      edgeSize: "s-1vcpu-512mb-10gb",
      edgeCount: 1,
      edges: [{ id: "edge-01", provider: "digitalocean", region: "sfo3", size: "s-1vcpu-512mb-10gb" }]
    });
    await waitFor(() => expect(fetchMock.mock.calls.some(([input, init]) => String(input).endsWith("/api/engagements/eng-zy01/revisions") && init?.method === "POST")).toBe(true));
  });

  it("explains the keyed Inspector provider restriction while retaining both provider choices", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ sketchStateSchema: "provider-keyed-v2" })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/credentials")) return Promise.resolve(jsonResponse({ credentials: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/inspector-settings")) return Promise.resolve(jsonResponse({ settings: observerSettingsFixture({ engagementId: "eng-zy01", provider: "digitalocean", region: "sfo3", size: "s-1vcpu-1gb" }) }));
      if (url.endsWith("/api/provider-catalog/sketch/region-policies")) return Promise.resolve(jsonResponse({ policies: {} }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: sketchCatalogFixture(provider) }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    expect(await screen.findByText("Keyed infrastructure requires a Linode Inspector. Select Linode before deployment.")).toBeInTheDocument();
    const provider = screen.getByLabelText("Inspector provider");
    expect(within(provider).getByRole("option", { name: "linode" })).toBeInTheDocument();
    expect(within(provider).getByRole("option", { name: "digitalocean" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save Inspector Settings" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Run Inspection Now" })).toBeDisabled();
    fireEvent.change(provider, { target: { value: "linode" } });
    expect(screen.queryByText("Keyed infrastructure requires a Linode Inspector. Select Linode before deployment.")).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Save Inspector Settings" })).toBeEnabled());
  });

  it("loads filtered catalogs once for Inspector and full catalogs only on Cloud Providers", async () => {
    let resolvePolicies!: (response: Response) => void;
    const fullCatalogResolvers = new Map<string, (response: Response) => void>();
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/credentials")) return Promise.resolve(jsonResponse({ credentials: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/inspector-settings")) return Promise.resolve(jsonResponse({ settings: observerSettingsFixture() }));
      if (url.endsWith("/api/provider-catalog/sketch/region-policies")) {
        return new Promise<Response>((resolve) => { resolvePolicies = resolve; });
      }
      if (url.includes("/api/provider-catalog/sketch?provider=")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        if (url.includes("includeBlocked=1")) {
          return new Promise<Response>((resolve) => fullCatalogResolvers.set(provider, resolve));
        }
        return Promise.resolve(jsonResponse({ catalog: providerCatalog(provider as "linode" | "digitalocean") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/provider-catalog/"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    await waitFor(() => expect(screen.getByLabelText("Inspector provider")).toBeEnabled());
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("/api/provider-catalog/sketch?provider=") && !String(input).includes("includeBlocked"))).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "General" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("/api/provider-catalog/sketch?provider=") && !String(input).includes("includeBlocked"))).toHaveLength(2);

    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Global Settings" }));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("includeBlocked"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Barragan App" }));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("includeBlocked"))).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    await waitFor(() => expect(fullCatalogResolvers.size).toBe(2));
    expect(screen.getByLabelText("linode us-sea")).toBeDisabled();
    fireEvent.change(screen.getByLabelText("DigitalOcean provider-smoke confirmation"), { target: { value: "validate-digitalocean-sketch" } });
    expect(screen.getByRole("button", { name: "Run Provider-Smoke Validation" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "User" }));
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("includeBlocked=1"))).toHaveLength(2);
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/api/provider-catalog/sketch/region-policies"))).toHaveLength(1);
    resolvePolicies(jsonResponse({ policies: [
      { provider: "linode", allowedRegions: ["us-sea"], createdAt: "", updatedAt: "" },
      { provider: "digitalocean", allowedRegions: ["sfo3"], createdAt: "", updatedAt: "" }
    ] }));
    fullCatalogResolvers.get("linode")!(jsonResponse({ catalog: providerCatalog("linode") }));
    fullCatalogResolvers.get("digitalocean")!(jsonResponse({ catalog: providerCatalog("digitalocean") }));
    await waitFor(() => expect(screen.getByLabelText("linode us-sea")).toBeEnabled());
    expect(screen.getByRole("button", { name: "Run Provider-Smoke Validation" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "User" }));
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("includeBlocked=1"))).toHaveLength(2);
  });

  it("shows a retryable provider-catalog failure in Infrastructure", async () => {
    let catalogAttempt = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) {
        catalogAttempt += 1;
        if (catalogAttempt <= 2) return Promise.reject(new Error("catalog unavailable"));
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: providerCatalog(provider as "linode" | "digitalocean") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Infrastructure changes remain disabled");
    expect(screen.getByLabelText("Infrastructure template")).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Retry Provider Catalog" }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(screen.getByLabelText("Infrastructure template")).toBeEnabled();
    expect(catalogAttempt).toBe(4);
  });

  it("shows a retryable provider-catalog failure in Inspector", async () => {
    let catalogAttempt = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/engagements/eng-zy01/inspector-settings")) return Promise.resolve(jsonResponse({ settings: observerSettingsFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) {
        catalogAttempt += 1;
        if (catalogAttempt <= 2) return Promise.reject(new Error("catalog unavailable"));
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: providerCatalog(provider as "linode" | "digitalocean") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Inspector provider settings remain disabled");
    expect(screen.getByLabelText("Inspector provider")).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Retry Provider Catalog" }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(screen.getByLabelText("Inspector provider")).toBeEnabled();
    expect(catalogAttempt).toBe(4);
  });

  it("does not let a stale filtered catalog win a forced policy refresh race", async () => {
    const filteredResolvers = new Map<string, Array<(response: Response) => void>>();
    const catalogForRegion = (regionId: "us-sea" | "us-ord") => {
      const catalog = providerCatalog("linode");
      return {
        ...catalog,
        defaults: { ...catalog.defaults, region: regionId },
        regions: catalog.regions.filter((region) => region.id === regionId)
      };
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/credentials")) return Promise.resolve(jsonResponse({ credentials: [] }));
      if (url.endsWith("/api/provider-catalog/sketch/region-policies")) {
        return Promise.resolve(jsonResponse({ policies: [
          { provider: "linode", allowedRegions: ["us-sea"], createdAt: "", updatedAt: "" },
          { provider: "digitalocean", allowedRegions: ["sfo3"], createdAt: "", updatedAt: "" }
        ] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch/region-policies/linode") && init?.method === "PATCH") {
        return Promise.resolve(jsonResponse({ policy: { provider: "linode", allowedRegions: ["us-ord", "us-sea"], createdAt: "", updatedAt: "" } }));
      }
      if (url.includes("includeBlocked=1")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: providerCatalog(provider as "linode" | "digitalocean") }));
      }
      if (url.includes("/api/provider-catalog/sketch?provider=")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return new Promise<Response>((resolve) => {
          const resolvers = filteredResolvers.get(provider) ?? [];
          resolvers.push(resolve);
          filteredResolvers.set(provider, resolvers);
        });
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(filteredResolvers.get("linode")).toHaveLength(1));

    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Global Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    await waitFor(() => expect(screen.getByLabelText("linode us-ord")).toBeEnabled());
    fireEvent.click(screen.getByLabelText("linode us-ord"));
    await waitFor(() => expect(filteredResolvers.get("linode")).toHaveLength(2));

    filteredResolvers.get("linode")![1](jsonResponse({ catalog: catalogForRegion("us-ord") }));
    filteredResolvers.get("digitalocean")![1](jsonResponse({ catalog: providerCatalog("digitalocean") }));
    await waitFor(() => expect(screen.getByText("Updated linode allowed regions.")).toBeInTheDocument());

    filteredResolvers.get("linode")![0](jsonResponse({ catalog: catalogForRegion("us-sea") }));
    filteredResolvers.get("digitalocean")![0](jsonResponse({ catalog: providerCatalog("digitalocean") }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    const middleRegion = await screen.findByLabelText("proxy01-chain-1 middle region") as HTMLSelectElement;
    expect(Array.from(middleRegion.options).map((option) => option.value)).toEqual(["us-ord"]);
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes("/api/provider-catalog/sketch?provider=") && !String(input).includes("includeBlocked"))).toHaveLength(4);
  });

  it("rejects incomplete Dashboard responses as ready", () => {
    const dashboard = emptyDashboardFixture();
    expect(dashboardResponseIsComplete(dashboard)).toBe(true);
    dashboard.systemHealth.disk.detail = "Loading";
    expect(dashboardResponseIsComplete(dashboard)).toBe(false);
    expect(dashboardResponseIsComplete({ ...emptyDashboardFixture(), engagementOverview: undefined } as never)).toBe(false);
  });

  it("reuses a pending Dashboard response when navigation returns before it settles", async () => {
    const resolvers: Array<(response: Response) => void> = [];
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return new Promise<Response>((resolve) => resolvers.push(resolve));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    const { container } = render(<StrictMode><App /></StrictMode>);
    await waitFor(() => expect(resolvers).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: "Engagements" }));
    fireEvent.click(screen.getByRole("button", { name: "Dashboard" }));
    expect(resolvers).toHaveLength(1);
    const initial = emptyDashboardFixture();
    initial.generatedAt = "2026-08-04T00:00:01Z";
    resolvers[0](jsonResponse({ dashboard: initial }));
    await waitFor(() => expect(container.querySelector("[data-dashboard-generated-at='2026-08-04T00:00:01Z']")).not.toBeNull());
    expect(resolvers).toHaveLength(1);
  });

  it("keeps a newer live Dashboard refresh authoritative over a pending initial response", async () => {
    let resolveInitial!: (response: Response) => void;
    let resolveLive!: (response: Response) => void;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return new Promise<Response>((resolve) => { resolveInitial = resolve; });
      if (url.endsWith("/api/dashboard?live=1")) return new Promise<Response>((resolve) => { resolveLive = resolve; });
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    const { container } = render(<App />);
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/api/dashboard"))).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: "Refresh Provider Inventory" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/api/dashboard?live=1"))).toBe(true));

    const live = emptyDashboardFixture();
    live.generatedAt = "2026-08-04T00:00:02Z";
    resolveLive(jsonResponse({ dashboard: live }));
    await waitFor(() => expect(container.querySelector("[data-dashboard-generated-at='2026-08-04T00:00:02Z']")).not.toBeNull());

    const initial = emptyDashboardFixture();
    initial.generatedAt = "2026-08-04T00:00:01Z";
    resolveInitial(jsonResponse({ dashboard: initial }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(container.querySelector("[data-dashboard-generated-at='2026-08-04T00:00:02Z']")).not.toBeNull();
    expect(container.querySelector("[data-dashboard-generated-at='2026-08-04T00:00:01Z']")).toBeNull();
  });

  it("emits the Dashboard-ready marker only for the rendered successful response", async () => {
    let resolveDashboard!: (response: Response) => void;
    const dashboardResponse = new Promise<Response>((resolve) => {
      resolveDashboard = resolve;
    });
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return dashboardResponse;
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    const { container } = render(<App />);
    expect(container.querySelector("[data-barragan-dashboard-ready]")).toBeNull();

    const dashboard = emptyDashboardFixture();
    dashboard.generatedAt = "2026-08-04T12:34:56Z";
    dashboard.summary.activeInfrastructure = 1;
    dashboard.engagementOverview.active = [{
      engagementId: "eng-perf",
      engagementName: "PERF01",
      engagementStatus: "active",
      lifecycleState: "deployed",
      healthStatus: "healthy",
      healthDetail: "Current",
      activeSince: "2026-08-01T00:00:00Z",
      activeDurationDays: 3,
      activeDurationLabel: "3 days",
      endedAt: null,
      archivedAt: null,
      providers: ["linode"],
      regions: ["us-sea"],
      lastCheckedAt: "2026-08-04T12:34:56Z"
    }];
    dashboard.systemHealth.api.detail = "API responding";
    resolveDashboard(jsonResponse({ dashboard }));

    await waitFor(() => expect(container.querySelector("[data-barragan-dashboard-ready]")).not.toBeNull());
    const marker = container.querySelector("[data-barragan-dashboard-ready]")!;
    expect(marker).toHaveAttribute("data-dashboard-generated-at", dashboard.generatedAt);
    expect(screen.getByLabelText("Barragan health")).toHaveTextContent("API responding");
    expect(screen.getByText("Active Infrastructure").nextElementSibling).toHaveTextContent("1");
    expect(screen.getByText("PERF01")).toBeInTheDocument();
  });

  it("shows unverified cleanup as attention rather than a verified success", async () => {
    const dashboard = emptyDashboardFixture();
    dashboard.engagementOverview.active = [{
      engagementId: "eng-cleanup", engagementName: "Cleanup review",
      lifecycleState: "cleanup_not_verified", healthStatus: "attention",
      activeDurationLabel: "3 days", providers: ["oci"], regions: ["us-sanjose-1"]
    }];
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      return Promise.resolve(jsonResponse({}));
    }));
    render(<App />);
    const badge = await screen.findByText("cleanup not verified");
    expect(badge).toHaveClass("attention");
    expect(badge).not.toHaveClass("healthy");
  });

  it("does not emit the Dashboard-ready marker for a failed response", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.reject(new Error("dashboard unavailable"));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    const { container } = render(<App />);
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/api/dashboard"))).toBe(true));
    expect(container.querySelector("[data-barragan-dashboard-ready]")).toBeNull();
    expect(screen.getByLabelText("Barragan health")).toHaveTextContent("Loading");
  });

  it("removes the ready marker while a provider refresh is pending and after it fails", async () => {
    let rejectRefresh!: (error: Error) => void;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/dashboard?live=1")) return new Promise<Response>((_resolve, reject) => { rejectRefresh = reject; });
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    const { container } = render(<App />);
    await waitFor(() => expect(container.querySelector("[data-barragan-dashboard-ready]")).not.toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Refresh Provider Inventory" }));
    expect(container.querySelector("[data-barragan-dashboard-ready]")).toBeNull();
    rejectRefresh(new Error("refresh failed"));
    await waitFor(() => expect(screen.getByText(/Provider inventory refresh failed/)).toBeInTheDocument());
    expect(container.querySelector("[data-barragan-dashboard-ready]")).toBeNull();
  });

  it("keeps personal settings available to read-only users without exposing administrator settings", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      return Promise.resolve(jsonResponse({}));
    });
    const onChangePassword = vi.fn();
    const onSignOut = vi.fn();
    const onSignOutAll = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    render(<App
      currentUser={{ id: "user-reader", username: "reader", displayName: "Read Only", roles: ["viewer"] }}
      onChangePassword={onChangePassword}
      onSignOut={onSignOut}
      onSignOutAll={onSignOutAll}
    />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    expect(screen.queryByLabelText("Signed in user")).not.toBeInTheDocument();
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Global Settings" }));

    expect(screen.getByRole("button", { name: "User" })).toHaveClass("active");
    expect(screen.getByLabelText("User settings")).toHaveTextContent("reader");
    expect(screen.getByLabelText("User settings")).toHaveTextContent("Read only");
    expect(screen.queryByRole("button", { name: "Cloud Providers" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Barragan App" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/credentials"))).toBe(false);
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/provider-catalog/sketch/region-policies"))).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    fireEvent.click(screen.getByRole("button", { name: "Sign out all sessions and tokens" }));
    expect(onChangePassword).toHaveBeenCalledOnce();
    expect(onSignOut).toHaveBeenCalledOnce();
    expect(onSignOutAll).toHaveBeenCalledOnce();
  });

  it("loads paginated job summaries only after the Jobs view opens", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.includes("/api/jobs?limit=50&offset=0")) {
        return Promise.resolve(jsonResponse({
          jobs: [{ id: "job-page-1", action: "first_page", status: "succeeded", target: "system:first", createdAt: "2026-07-08T00:00:00+00:00" }],
          pagination: { total: 51, limit: 50, offset: 0, hasMore: true }
        }));
      }
      if (url.includes("/api/jobs?limit=50&offset=50")) {
        return Promise.resolve(jsonResponse({
          jobs: [{ id: "job-page-2", action: "second_page", status: "succeeded", target: "system:second", createdAt: "2026-07-07T00:00:00+00:00" }],
          pagination: { total: 51, limit: 50, offset: 50, hasMore: false }
        }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/jobs"))).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Jobs" }));
    await waitFor(() => expect(screen.getByText("first_page")).toBeInTheDocument());
    expect(screen.getByText("Showing 1-1 of 51 jobs.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(screen.getByText("second_page")).toBeInTheDocument());
    expect(screen.getByText("Showing 51-51 of 51 jobs.")).toBeInTheDocument();
  });

  it("configures OPSEC network restrictions from Capabilities and reopens the progress log", async () => {
    const applyBodies: Array<Record<string, unknown>> = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "0.1.0", description: "Baseline", defaultNodeGroups: ["homebase"], supportedProviders: ["oci"] }] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-zy01", name: "ZY01", status: "draft", owner: "operator", templateId: "standard-rti", activeRevision: "rev-1" }] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-07-20T00:00:00+00:00",
            summary: { templates: 1, engagements: 1, activeEngagements: 1, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0, recentTeardowns: 0, recentArchives: 0 },
            engagementOverview: { windowDays: 30, active: [], recentlyEnded: [], recentlyArchived: [] },
            systemHealth: {},
            inventory: [],
            orphanCandidates: [],
            reconciliation: { status: "local-records", detail: "Local records." }
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: opsecCapabilityWorkspace() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/opsec-network-restrictions") && init?.method !== "POST") {
        return Promise.resolve(jsonResponse({
          service: opsecService("Disabled"),
          configuration: { enabled: false, destinations: [], notes: "", purpose: "", managedComment: "barragan-opsec-network-restrictions" }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/opsec-network-restrictions/apply") && init?.method === "POST") {
        applyBodies.push(JSON.parse(String(init.body ?? "{}")));
        return Promise.resolve(jsonResponse({
          job: opsecJob("running"),
          status: "Applying",
          service: opsecService("Applying"),
          configuration: {
            enabled: true,
            destinations: ["10.10.0.0/24", "203.0.113.7"],
            notes: "client ranges",
            purpose: "avoid direct Homebase traffic",
            managedComment: "barragan-opsec-network-restrictions"
          }
        }));
      }
      if (url.endsWith("/api/jobs/job-opsec-apply")) {
        return Promise.resolve(jsonResponse({ job: opsecJob("succeeded") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    const workspaceNav = screen.getByRole("navigation", { name: "Engagement workspace sections" });
    fireEvent.click(within(workspaceNav).getByRole("button", { name: "Capabilities" }));
    await screen.findByText("OPSEC network restrictions");
    fireEvent.click(screen.getByRole("button", { name: /OPSEC network restrictions/ }));

    const panel = await screen.findByRole("region", { name: "Configure OPSEC network restrictions" });
    fireEvent.click(within(panel).getByLabelText("Enable OPSEC network restrictions"));
    fireEvent.change(within(panel).getByLabelText("OPSEC blocked destinations"), {
      target: { value: "10.10.0.0/24\n203.0.113.7" }
    });
    fireEvent.change(within(panel).getByLabelText("OPSEC purpose"), {
      target: { value: "avoid direct Homebase traffic" }
    });
    fireEvent.change(within(panel).getByLabelText("OPSEC notes"), {
      target: { value: "client ranges" }
    });
    fireEvent.click(within(panel).getByRole("button", { name: "Apply OPSEC Restrictions" }));

    await waitFor(() => expect(applyBodies).toHaveLength(1));
    expect(applyBodies[0]).toEqual({
      enabled: true,
      destinations: ["10.10.0.0/24", "203.0.113.7"],
      notes: "client ranges",
      purpose: "avoid direct Homebase traffic"
    });
    const consolePanel = await screen.findByRole("region", { name: "OPSEC job console" });
    expect(consolePanel).toHaveTextContent("Prepared OPSEC network restrictions workspace for homebase.");
    fireEvent.click(within(consolePanel).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "OPSEC job console" })).not.toBeInTheDocument());
    fireEvent.click(within(panel).getByRole("button", { name: "Log" }));
    expect(await screen.findByRole("region", { name: "OPSEC job console" })).toHaveTextContent("Started OPSEC Ansible apply on homebase.");
  });

  it("renders the operator shell with API data", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/api/templates")) {
          return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "0.1.0", description: "Baseline", defaultNodeGroups: ["homebase"], supportedProviders: ["oci"] }] }));
        }
        if (url.endsWith("/api/engagements?scope=all")) {
          return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-1", name: "of02-dev reference", status: "observed", owner: "infrastructure", templateId: "standard-rti", activeRevision: "rev-1" }] }));
        }
        if (url.endsWith("/api/dashboard")) {
          return Promise.resolve(jsonResponse({
            dashboard: {
              generatedAt: "2026-06-08T00:00:00+00:00",
              summary: {
                templates: 1,
                engagements: 1,
                activeEngagements: 1,
                jobRuns: 1,
                activeInfrastructure: 1,
                attention: 0,
                destroyed: 0,
                lastKnown: 0,
                orphanCandidates: 0,
                recentTeardowns: 1,
                recentArchives: 1
              },
              engagementOverview: {
                windowDays: 30,
                active: [
                  {
                    engagementId: "eng-1",
                    engagementName: "of02-dev reference",
                    engagementStatus: "observed",
                    lifecycleState: "active",
                    healthStatus: "healthy",
                    healthDetail: "Active infrastructure.",
                    activeSince: "2026-06-01T00:00:00+00:00",
                    activeDurationDays: 7,
                    activeDurationLabel: "7 days",
                    endedAt: null,
                    archivedAt: null,
                    providers: ["oci", "linode"],
                    regions: ["us-sanjose-1", "us-sea"],
                    lastCheckedAt: "2026-06-08T00:00:00+00:00"
                  }
                ],
                recentlyEnded: [
                  {
                    engagementId: "eng-old",
                    engagementName: "old-prod",
                    engagementStatus: "planned",
                    lifecycleState: "destroyed",
                    healthStatus: "destroyed",
                    healthDetail: "Infrastructure is torn down.",
                    activeSince: "2026-05-01T00:00:00+00:00",
                    activeDurationDays: 20,
                    activeDurationLabel: "20 days",
                    endedAt: "2026-06-07T00:00:00+00:00",
                    archivedAt: null,
                    providers: ["oci"],
                    regions: ["us-sanjose-1"],
                    lastCheckedAt: "2026-06-07T00:00:00+00:00"
                  }
                ],
                recentlyArchived: [
                  {
                    engagementId: "eng-archive",
                    engagementName: "archived-prod",
                    engagementStatus: "retired",
                    lifecycleState: "archived",
                    healthStatus: "archived",
                    healthDetail: "Engagement is archived.",
                    activeSince: null,
                    activeDurationDays: null,
                    activeDurationLabel: "not recorded",
                    endedAt: null,
                    archivedAt: "2026-06-06T00:00:00+00:00",
                    providers: [],
                    regions: [],
                    lastCheckedAt: null
                  }
                ]
              },
              systemHealth: {
                api: { status: "ok", detail: "Barragan API is responding.", checkedAt: "2026-06-08T00:00:00+00:00" },
                database: { status: "ok", detail: "Database query succeeded.", uriScheme: "sqlite", path: "/tmp/barragan.db", seedStatus: "seeded" },
                disk: { status: "ok", detail: "42% disk used at /tmp.", path: "/tmp", freeBytes: 1, totalBytes: 2, usedPercent: 42 },
                providers: { status: "not checked", detail: "Provider connectivity has not been checked.", checkedAt: null }
              },
              inventory: [
                {
                  engagementId: "eng-1",
                  engagementName: "of02-dev reference",
                  engagementStatus: "observed",
                  lifecycleState: "active",
                  healthStatus: "healthy",
                  coreHostCount: 3,
                  activeCoreHostCount: 3,
                  sketchHostCount: 2,
                  activeSketchHostCount: 2,
                  outboundChannelCount: 2,
                  inboundChannelCount: 1,
                  providers: ["oci", "linode"],
                  regions: ["us-sanjose-1", "us-sea"],
                  lastCheckedAt: "2026-06-08T00:00:00+00:00",
                  lastKnown: false,
                  attention: false,
                  detail: "Active infrastructure."
                }
              ],
              orphanCandidates: [],
              reconciliation: {
                status: "local-records",
                detail: "Dashboard inventory is derived from Barragan runtime records."
              }
            }
          }));
        }
        return Promise.resolve(jsonResponse({ jobs: [{ id: "job-1", action: "capture_reference", status: "succeeded", target: "of02-dev reference", createdAt: "2026-05-31T00:00:00+00:00" }] }));
      })
    );

    render(<App />);

    expect(screen.getByRole("heading", { name: "Barragan" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    expect(screen.getByLabelText("Active engagement")).toHaveValue("eng-1");
    expect(screen.getByLabelText("Active engagement")).toHaveDisplayValue("of02-dev reference");
    expect(screen.queryByText("Switch engagement")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Engagements" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New Engagement" })).not.toBeInTheDocument();
    expect(screen.getByText("Engagement Activity")).toBeInTheDocument();
    expect(screen.getByLabelText("Active engagement summary")).toHaveTextContent("of02-dev reference");
    expect(screen.getByLabelText("Active engagement summary")).toHaveTextContent("7 days");
    expect(screen.getByLabelText("Active engagement summary")).toHaveTextContent("oci, linode");
    expect(screen.getByLabelText("Recent engagement changes")).toHaveTextContent("old-prod");
    expect(screen.getByLabelText("Recent engagement changes")).toHaveTextContent("archived-prod");
    expect(screen.getByText("Barragan Health")).toBeInTheDocument();
    expect(screen.getByLabelText("Barragan health")).toHaveTextContent("Database query succeeded.");
    expect(screen.getByText("Active Infrastructure")).toBeInTheDocument();
    expect(screen.getByText("Provider Findings")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Plan Preview" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Test Deploy" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Channels" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Service Instances" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Team" })).toHaveLength(2);
    expect(screen.queryByRole("button", { name: "Plan" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Deployments" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Access" })).not.toBeInTheDocument();
  });

  it("uses table-first Global Team modals and previews users imports", async () => {
    const now = "2026-06-24T00:00:00+00:00";
    const usersJsonContent = readFileSync("../spec/ssh/users.json", "utf-8");
    const teamMember = {
      id: "user-aluvshis",
      username: "aluvshis",
      displayName: "Adam Luvshis",
      email: "aluvshis@example.invalid",
      status: "active",
      defaultInfraGroups: ["redteam", "core"],
      globalRoles: ["operator"],
      sshKeys: [
        {
          id: "key-aluvshis",
          label: "piv",
          fingerprint: "SHA256:aluvshis",
          status: "active",
          publicKey: "ssh-ed25519 dGVzdC1wdWJsaWMta2V5 aluvshis",
          createdAt: now,
          retiredAt: null
        }
      ],
      createdAt: now,
      updatedAt: now,
      deactivatedAt: null
    };
    const teamWorkspace = {
      members: [teamMember],
      supportedInfraGroups: ["redteam", "core", "volunteer", "infra"],
      defaultInfraGroups: ["redteam", "volunteer"],
      supportedGlobalRoles: ["operator", "infrastructure_manager", "approver", "administrator", "service_account"],
      supportedAppPrivileges: ["view", "operate", "approve_destructive", "administer"]
    };
    const importPreview = {
      format: "json",
      fileName: "users.json",
      summary: { creates: 1, updates: 0, unchanged: 1, invalid: 0, keyAdditions: 1 },
      warnings: ["Import is conservative: users missing from the file are not deactivated and existing SSH keys missing from the file are not retired."],
      records: [
        {
          sourceIndex: 1,
          username: "newuser",
          displayName: "New User",
          defaultInfraGroups: ["redteam", "volunteer"],
          sshKeys: [],
          errors: [],
          action: "create",
          memberId: "",
          changes: [],
          keyAdditions: 1,
          existingKeyCount: 0
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: now,
            summary: { templates: 0, engagements: 1, activeEngagements: 0, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0 },
            inventory: [],
            orphanCandidates: [],
            reconciliation: { status: "local-records", detail: "Test." }
          }
        }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/team/import/preview") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ preview: importPreview }));
      }
      if (url.endsWith("/api/team/import/apply") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          preview: importPreview,
          applied: { created: ["newuser"], updated: [], unchanged: ["aluvshis"], skipped: [], keyAdditions: 1 },
          team: { ...teamWorkspace, members: [...teamWorkspace.members, { ...teamMember, id: "user-newuser", username: "newuser", displayName: "New User", sshKeys: [] }] }
        }));
      }
      if (url.endsWith("/api/team")) {
        return Promise.resolve(jsonResponse(teamWorkspace));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getAllByRole("button", { name: "Team" })[1]);

    await waitFor(() => expect(screen.getByLabelText("Global team members")).toHaveTextContent("aluvshis"));
    expect(screen.getByLabelText("Global team members")).toHaveTextContent("User ID");
    expect(screen.queryByLabelText("Global team member form")).not.toBeInTheDocument();

    fireEvent.click(within(screen.getByLabelText("Global team members")).getByRole("button", { name: "Configure" }));
    expect(screen.getByLabelText("Configure team member")).toHaveTextContent("Configure aluvshis");
    expect(screen.getByLabelText("Configure team member")).toHaveTextContent("SSH Public Keys");
    fireEvent.click(within(screen.getByLabelText("Configure team member")).getByRole("button", { name: "Close" }));

    fireEvent.click(screen.getByRole("button", { name: "Create Member" }));
    expect(screen.getByLabelText("Create team member")).toHaveTextContent("Create Member");
    fireEvent.click(within(screen.getByLabelText("Create team member")).getByRole("button", { name: "Close" }));

    fireEvent.click(screen.getByRole("button", { name: "Import Users" }));
    expect(screen.getByLabelText("Import users")).toHaveTextContent("1. Select File");
    expect(screen.getByLabelText("Import users")).toHaveTextContent("Select users.json or users.yml");
    expect(screen.queryByLabelText("Users import content")).not.toBeInTheDocument();
    const usersFile = new File([usersJsonContent], "users.json", { type: "application/json" });
    Object.defineProperty(usersFile, "text", { value: () => Promise.resolve(usersJsonContent) });
    fireEvent.change(screen.getByLabelText("Users import file"), {
      target: { files: [usersFile] }
    });
    await waitFor(() => expect(screen.getByLabelText("Selected users import file")).toHaveTextContent("users.json"));
    fireEvent.click(screen.getByRole("button", { name: "Preview Changes" }));

    await waitFor(() => expect(screen.getByLabelText("Users import preview")).toHaveTextContent("newuser"));
    expect(screen.getByLabelText("Import users")).toHaveTextContent("2. Preview Changes");
    expect(screen.getByText("Import is conservative: users missing from the file are not deactivated and existing SSH keys missing from the file are not retired.")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/\/api\/team\/import\/preview$/), expect.objectContaining({
      body: expect.stringContaining("example_operator_two")
    }));

    fireEvent.click(screen.getByRole("button", { name: "Apply Changes" }));
    await waitFor(() => expect(screen.getByText("1 created, 0 updated, 1 SSH keys added, 0 skipped.")).toBeInTheDocument());
    expect(screen.getByLabelText("Import users")).toHaveTextContent("3. Apply Changes");
  });

  it("explicitly reactivates a deactivated global member and handles failure", async () => {
    const member = { id: "user-returning", username: "returning", displayName: "Returning Operator", email: "", status: "deactivated", desiredUid: 6201, defaultInfraGroups: ["redteam"], globalRoles: ["operator"], sshKeys: [], createdAt: "", updatedAt: "", deactivatedAt: "2026-10-27" };
    let fail = true;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/team/user-returning") && init?.method === "PATCH") {
        return Promise.resolve(fail ? errorResponse(403, { errors: ["Reactivation denied"] }) : jsonResponse({ member: { ...member, status: "active", deactivatedAt: null } }));
      }
      if (url.endsWith("/api/team")) return Promise.resolve(jsonResponse({ members: [member], supportedInfraGroups: ["redteam"], defaultInfraGroups: ["redteam"], supportedAppPrivileges: [] }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    fireEvent.click(screen.getAllByRole("button", { name: "Team" }).at(-1)!);
    await waitFor(() => expect(screen.getByLabelText("Global team members")).toHaveTextContent("returning"));
    fireEvent.click(screen.getByRole("button", { name: "Configure" }));
    expect(screen.getByLabelText("Team member account status")).toHaveTextContent("Adding or editing SSH keys does not reactivate");
    expect(screen.queryByRole("button", { name: "Deactivate Member" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reactivate Member" }));
    await waitFor(() => expect(screen.getByText(/Reactivation denied/)).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Reactivate Member" })).toBeEnabled();
    fail = false;
    fireEvent.click(screen.getByRole("button", { name: "Reactivate Member" }));
    await waitFor(() => expect(screen.getByText(/returning reactivated/)).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(/api\/team\/user-returning$/), expect.objectContaining({ method: "PATCH", body: JSON.stringify({ status: "active" }) }));
    fireEvent.click(screen.getByRole("button", { name: "Configure" }));
    expect(screen.getByRole("button", { name: "Deactivate Member" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Reactivate Member" })).not.toBeInTheDocument();
  });

  it("uses table-first Engagement Team include and configure modals", async () => {
    const now = "2026-06-24T00:00:00+00:00";
    const activeMember = {
      id: "user-operator",
      username: "operator1",
      displayName: "Operator One",
      email: "operator1@example.invalid",
      status: "active",
      defaultInfraGroups: ["redteam", "volunteer"],
      globalRoles: ["operator"],
      sshKeys: [
        {
          id: "key-operator",
          label: "piv",
          fingerprint: "SHA256:operator1",
          status: "active",
          publicKey: "ssh-ed25519 dGVzdC1wdWJsaWMta2V5 operator1",
          createdAt: now,
          retiredAt: null
        }
      ],
      createdAt: now,
      updatedAt: now,
      deactivatedAt: null
    };
    const availableMember = {
      ...activeMember,
      id: "user-available",
      username: "operator2",
      displayName: "Operator Two",
      email: "operator2@example.invalid",
      sshKeys: []
    };
    const deactivatedMember = {
      ...activeMember,
      id: "user-deactivated",
      username: "departed",
      displayName: "Departed Operator",
      status: "deactivated",
      deactivatedAt: now
    };
    const membership = {
      id: "membership-operator",
      engagementId: "eng-zy01",
      memberId: activeMember.id,
      member: activeMember,
      appPrivileges: ["view", "operate"],
      infraAccessEnabled: true,
      infraGroupsOverride: null,
      effectiveInfraGroups: ["redteam", "volunteer"],
      targetScope: "homebase_and_proxies",
      targetHosts: ["homebase", "proxy01", "proxy02"],
      status: "active",
      infrastructureState: "pending_enable",
      applyJobId: "",
      createdAt: now,
      updatedAt: now,
      removedAt: null
    };
    let engagementTeamWorkspace = {
      engagementId: "eng-zy01",
      memberships: [membership],
      availableMembers: [activeMember, availableMember, deactivatedMember],
      supportedInfraGroups: ["redteam", "core", "volunteer", "infra"],
      supportedAppPrivileges: ["view", "operate", "approve_destructive", "administer"],
      defaultTargets: ["homebase", "proxy01", "proxy02"]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: now,
            summary: { templates: 0, engagements: 1, activeEngagements: 1, jobRuns: 0, activeInfrastructure: 0, attention: 0, destroyed: 0, lastKnown: 0, orphanCandidates: 0 },
            inventory: [],
            orphanCandidates: [],
            reconciliation: { status: "local-records", detail: "Test." }
          }
        }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/team/access-apply") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          status: "running",
          plan: {
            mode: "live-apply",
            liveApply: true,
            targetHosts: ["homebase", "proxy01", "proxy02"],
            sketchTargets: [],
            sudoGroup: "redteam",
            coreUsers: [],
            disabledUsers: [],
            warnings: [],
            summary: "1 active core user."
          },
          job: {
            id: "job-team-access",
            action: "engagement_access_apply",
            status: "running",
            targetType: "engagement",
            targetId: "eng-zy01",
            requestedBy: "operator",
            input: {},
            artifactRefs: [],
            events: [
              { sequence: 1, level: "info", message: "core access workspace rendered", data: {} },
              { sequence: 2, level: "info", message: "core host targets selected", data: { targetHosts: ["homebase", "proxy01", "proxy02"] } },
              { sequence: 3, level: "info", message: "sketch targets omitted for OPSEC", data: {} },
              { sequence: 4, level: "info", message: "core access Ansible apply started", data: { enableUsers: ["operator1"], disableUsers: [] } }
            ]
          }
        }));
      }
      if (url.endsWith("/api/jobs/job-team-access")) {
        engagementTeamWorkspace = {
          ...engagementTeamWorkspace,
          memberships: engagementTeamWorkspace.memberships.map((candidate) => ({
            ...candidate,
            infrastructureState: candidate.infrastructureState === "pending_enable" ? "enabled" : candidate.infrastructureState,
            applyJobId: "job-team-access"
          }))
        };
        return Promise.resolve(jsonResponse({
          job: {
            id: "job-team-access",
            action: "engagement_access_apply",
            status: "succeeded",
            targetType: "engagement",
            targetId: "eng-zy01",
            requestedBy: "operator",
            input: {},
            artifactRefs: [],
            events: [
              { sequence: 1, level: "info", message: "core access workspace rendered", data: {} },
              { sequence: 2, level: "info", message: "core host targets selected", data: { targetHosts: ["homebase", "proxy01", "proxy02"] } },
              { sequence: 3, level: "info", message: "sketch targets omitted for OPSEC", data: {} },
              { sequence: 4, level: "info", message: "core access Ansible apply started", data: { enableUsers: ["operator1"], disableUsers: [] } },
              { sequence: 5, level: "info", message: "core access Ansible apply succeeded", data: { enabledUsers: ["operator1"], disabledUsers: [], commandResult: { returncode: 0 } } }
            ]
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/team") && init?.method === "POST") {
        const body = JSON.parse(String(init.body));
        const member = engagementTeamWorkspace.availableMembers.find((candidate) => candidate.id === body.memberId) ?? availableMember;
        const includedMembership = {
          ...membership,
          id: "membership-operator2",
          memberId: member.id,
          member,
          appPrivileges: ["view"],
          effectiveInfraGroups: member.defaultInfraGroups,
          infrastructureState: "pending_enable"
        };
        engagementTeamWorkspace = {
          ...engagementTeamWorkspace,
          memberships: [...engagementTeamWorkspace.memberships, includedMembership]
        };
        return Promise.resolve(jsonResponse({ ...engagementTeamWorkspace, membership: includedMembership }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/team/membership-operator") && init?.method === "PATCH") {
        const body = JSON.parse(String(init.body));
        const updatedMembership = {
          ...membership,
          infraGroupsOverride: body.infraGroupsOverride ?? null,
          effectiveInfraGroups: body.infraGroupsOverride ?? membership.effectiveInfraGroups,
          status: body.status ?? membership.status,
          infrastructureState: "pending_enable"
        };
        engagementTeamWorkspace = { ...engagementTeamWorkspace, memberships: [updatedMembership] };
        return Promise.resolve(jsonResponse({ ...engagementTeamWorkspace, membership: updatedMembership }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/team")) {
        return Promise.resolve(jsonResponse(engagementTeamWorkspace));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getAllByRole("button", { name: "Team" })[0]);

    await waitFor(() => expect(screen.getByLabelText("Engagement team memberships")).toHaveTextContent("operator1"));
    expect(screen.getByLabelText("Engagement team memberships")).toHaveTextContent("User ID");
    expect(screen.getByLabelText("Engagement team memberships")).toHaveTextContent("Linux Groups");
    expect(screen.getByLabelText("Engagement team memberships")).toHaveTextContent("Pending Enable");
    expect(screen.queryByLabelText("Engagement team membership form")).not.toBeInTheDocument();
    expect(screen.queryByText("Barragan app privileges")).not.toBeInTheDocument();
    expect(screen.queryByText("App Privileges")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Include Operator" }));
    expect(screen.getByLabelText("Include operator")).toHaveTextContent("operator2");
    expect(screen.getByLabelText("Include operator")).not.toHaveTextContent("departed");
    fireEvent.click(screen.getByLabelText("Select all visible operators"));
    expect(screen.getByLabelText("Include operator")).toHaveTextContent("1 selected");
    fireEvent.click(screen.getByRole("button", { name: "Include Selected" }));

    await waitFor(() => expect(screen.getByLabelText("Engagement team memberships")).toHaveTextContent("operator2"));
    const includeCall = fetchMock.mock.calls.find((call) => String(call[0]).endsWith("/api/engagements/eng-zy01/team") && call[1]?.method === "POST");
    expect(String(includeCall?.[1]?.body)).not.toContain("appPrivileges");

    fireEvent.click(within(screen.getByLabelText("Engagement team memberships")).getAllByRole("button", { name: "Configure" })[0]);
    expect(screen.getByLabelText("Configure engagement operator")).toHaveTextContent("Configure operator1");
    expect(screen.getByLabelText("Configure engagement operator")).toHaveTextContent("Active SSH keys");
    expect(screen.getByLabelText("Configure engagement operator")).not.toHaveTextContent("Barragan app privileges");
    fireEvent.click(screen.getByLabelText("Inherit global infrastructure groups"));
    expect(screen.getByLabelText("Engagement infrastructure groups")).toHaveTextContent("infra");
    fireEvent.click(within(screen.getByLabelText("Configure engagement operator")).getByRole("button", { name: "Close" }));
    expect(screen.getByRole("button", { name: "Apply Access Changes" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Apply Access Changes" }));
    await waitFor(() => expect(screen.getByLabelText("Core access job console")).toHaveTextContent("Started Ansible core access apply"));
    await waitFor(() => expect(screen.getByLabelText("Core access job console")).toHaveTextContent("Core-host access apply succeeded"));
    await waitFor(() => expect(screen.getByLabelText("Engagement team memberships")).toHaveTextContent("Enabled"));
    fireEvent.click(within(screen.getByLabelText("Core access job console")).getByRole("button", { name: "Close" }));
    expect(screen.queryByLabelText("Core access job console")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "View Console" }));
    expect(screen.getByLabelText("Core access job console")).toHaveTextContent("job job-team-access");
  });

  it("shows provider orphan candidates on the global dashboard", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-or01", name: "OR01", status: "planned", owner: "codex", templateId: "standard-rti", activeRevision: null }] }));
      }
      if (url.endsWith("/api/dashboard/orphan-candidates/actions") && init?.method === "POST") {
        const requestBody = JSON.parse(String(init.body || "{}"));
        if (requestBody.action === "tear_down" && requestBody.mutation) {
          return Promise.resolve(jsonResponse({
            candidate: orphanCandidateFixture(),
            status: "succeeded",
            confirmationToken: "tear-down-oci-compute-instance-ocid1-instance-orphan",
            job: {
              id: "job-orphan-teardown",
              action: "provider_orphan_teardown",
              status: "succeeded",
              targetType: "provider_orphan",
              targetId: "oci:compute_instance:ocid1.instance.orphan",
              requestedBy: "operator",
              input: {},
              artifactRefs: [],
              events: [
                {
                  sequence: 1,
                  level: "info",
                  message: "provider orphan teardown requested",
                  data: {}
                },
                {
                  sequence: 2,
                  level: "info",
                  message: "provider resource delete requested",
                  data: {}
                }
              ]
            }
          }));
        }
        if (requestBody.action === "tear_down") {
          return Promise.resolve(jsonResponse({
            candidate: orphanCandidateFixture(),
            status: "planned",
            confirmationToken: "tear-down-oci-compute-instance-ocid1-instance-orphan",
            job: {
              id: "job-orphan-teardown-plan",
              action: "provider_orphan_teardown_plan",
              status: "succeeded",
              targetType: "provider_orphan",
              targetId: "oci:compute_instance:ocid1.instance.orphan",
              requestedBy: "operator",
              input: {},
              artifactRefs: [],
              events: [
                {
                  sequence: 1,
                  level: "info",
                  message: "provider orphan teardown plan recorded",
                  data: {}
                }
              ]
            }
          }));
        }
        return Promise.resolve(jsonResponse({
          candidate: orphanCandidateFixture(),
          status: "tracked",
          confirmationToken: "tear-down-oci-compute-instance-ocid1-instance-orphan",
          job: {
            id: "job-orphan-track",
            action: "provider_orphan_track",
            status: "succeeded",
            targetType: "provider_orphan",
            targetId: "oci:compute_instance:ocid1.instance.orphan",
            requestedBy: "operator",
            input: {},
            artifactRefs: [],
            events: [
              {
                sequence: 1,
                level: "info",
                message: "provider resource tracked in Barragan records",
                data: {}
              }
            ]
          }
        }));
      }
      if (url.endsWith("/api/dashboard?live=1")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-06-09T00:00:00+00:00",
            summary: {
              templates: 0,
              engagements: 1,
              activeEngagements: 1,
              jobRuns: 1,
              activeInfrastructure: 0,
              attention: 0,
              destroyed: 0,
              lastKnown: 0,
              orphanCandidates: 1
            },
            inventory: [],
            orphanCandidates: [orphanCandidateFixture()],
            reconciliation: {
              status: "provider-reconciled",
              detail: "Provider inventory found active Barragan-owned resources that are not backed by active local deployment state."
            }
          }
        }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-06-09T00:00:00+00:00",
            summary: {
              templates: 0,
              engagements: 1,
              activeEngagements: 1,
              jobRuns: 1,
              activeInfrastructure: 0,
              attention: 0,
              destroyed: 0,
              lastKnown: 0,
              orphanCandidates: 0
            },
            inventory: [],
            orphanCandidates: [],
            reconciliation: {
              status: "local-records",
              detail: "Dashboard inventory is derived from Barragan runtime records."
            }
          }
        }));
      }
      return Promise.resolve(jsonResponse({ jobs: [{ id: "job-orphan-track", action: "provider_orphan_track", status: "succeeded", target: "homebase-or01", createdAt: "2026-06-09T00:00:00+00:00" }] }));
    });
    vi.stubGlobal(
      "fetch",
      fetchMock
    );

    render(<App />);

    await waitFor(() => expect(screen.getAllByText("local-records").length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole("button", { name: "Refresh Provider Inventory" }));
    await waitFor(() => expect(screen.getAllByText("provider-reconciled").length).toBeGreaterThan(0));
    const orphanTable = screen.getByLabelText("Provider orphan candidates");
    expect(orphanTable).toHaveTextContent("OR01");
    expect(orphanTable).toHaveTextContent("homebase-or01");
    expect(orphanTable).toHaveTextContent("RUNNING");
    expect(orphanTable).toHaveTextContent("no active local deployment state");
    expect(within(orphanTable).getByRole("button", { name: "Track" })).toBeInTheDocument();
    expect(within(orphanTable).getByRole("button", { name: "Teardown Plan" })).toBeInTheDocument();

    fireEvent.click(within(orphanTable).getByRole("button", { name: "Track" }));

    await waitFor(() => expect(screen.getByText(/provider resource tracked in Barragan records/i)).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/dashboard/orphan-candidates/actions",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          candidateId: "oci:compute_instance:ocid1.instance.orphan",
          action: "track",
          requestedBy: "operator"
        })
      })
    );

    fireEvent.click(within(orphanTable).getByRole("button", { name: "Teardown Plan" }));
    await waitFor(() => expect(screen.getByText(/Confirmation token: tear-down-oci-compute-instance-ocid1-instance-orphan/i)).toBeInTheDocument());
    const confirmButton = screen.getByRole("button", { name: "Confirm Teardown" });
    expect(confirmButton).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Live teardown confirmation for homebase-or01"), {
      target: { value: "tear-down-oci-compute-instance-ocid1-instance-orphan" }
    });
    expect(confirmButton).not.toBeDisabled();
    fireEvent.click(confirmButton);

    await waitFor(() => expect(screen.getAllByText(/provider resource delete requested/i).length).toBeGreaterThan(0));
    const recoveryConsole = screen.getByLabelText("Provider recovery progress");
    expect(recoveryConsole).toHaveTextContent("job-orphan-teardown");
    fireEvent.click(within(recoveryConsole).getByRole("button", { name: "Close" }));
    expect(screen.queryByLabelText("Provider recovery progress")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Log" }));
    expect(screen.getByLabelText("Provider recovery progress")).toHaveTextContent("provider resource delete requested");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/dashboard/orphan-candidates/actions",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          candidateId: "oci:compute_instance:ocid1.instance.orphan",
          action: "tear_down",
          requestedBy: "operator",
          mutation: true,
          confirmation: "tear-down-oci-compute-instance-ocid1-instance-orphan"
        })
      })
    );
  });

  it("shows unmanaged RTI findings without teardown controls", async () => {
    const unmanagedFinding = orphanCandidateFixture({
      candidateId: "oci:compute_instance:ocid1.instance.manual",
      resourceId: "ocid1.instance.manual",
      classification: "unmanaged_rti",
      reason:
        "Provider inventory found RTI-looking infrastructure for this engagement, but it does not carry Barragan ownership tags. Treat it as manually managed unless an operator explicitly tracks it.",
      actions: ["track", "mark_destroyed"]
    });
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/api/templates")) {
          return Promise.resolve(jsonResponse({ templates: [] }));
        }
        if (url.endsWith("/api/engagements?scope=all")) {
          return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-or01", name: "OR01", status: "planned", owner: "codex", templateId: "standard-rti", activeRevision: null }] }));
        }
        if (url.endsWith("/api/dashboard?live=1")) {
          return Promise.resolve(jsonResponse({
            dashboard: {
              generatedAt: "2026-06-09T00:00:00+00:00",
              summary: {
                templates: 0,
                engagements: 1,
                activeEngagements: 1,
                jobRuns: 1,
                activeInfrastructure: 0,
                attention: 0,
                destroyed: 0,
                lastKnown: 0,
                orphanCandidates: 1
              },
              inventory: [],
              orphanCandidates: [unmanagedFinding],
              reconciliation: {
                status: "provider-reconciled",
                detail: "Provider inventory found active resources that require operator review."
              }
            }
          }));
        }
        if (url.endsWith("/api/dashboard")) {
          return Promise.resolve(jsonResponse({
            dashboard: {
              generatedAt: "2026-06-09T00:00:00+00:00",
              summary: {
                templates: 0,
                engagements: 1,
                activeEngagements: 1,
                jobRuns: 1,
                activeInfrastructure: 0,
                attention: 0,
                destroyed: 0,
                lastKnown: 0,
                orphanCandidates: 0
              },
              inventory: [],
              orphanCandidates: [],
              reconciliation: {
                status: "local-records",
                detail: "Dashboard inventory is derived from Barragan runtime records."
              }
            }
          }));
        }
        return Promise.resolve(jsonResponse({ jobs: [] }));
      })
    );

    render(<App />);

    await waitFor(() => expect(screen.getAllByText("local-records").length).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole("button", { name: "Refresh Provider Inventory" }));
    await waitFor(() => expect(screen.getAllByText("provider-reconciled").length).toBeGreaterThan(0));
    const orphanTable = screen.getByLabelText("Provider orphan candidates");
    expect(orphanTable).toHaveTextContent("does not carry Barragan ownership tags");
    expect(within(orphanTable).getByRole("button", { name: "Track" })).toBeInTheDocument();
    expect(within(orphanTable).getByRole("button", { name: "Record Destroyed Note" })).toBeInTheDocument();
    expect(within(orphanTable).queryByRole("button", { name: "Teardown Plan" })).not.toBeInTheDocument();
  });

  it("switches the active engagement from the sidebar workspace selector", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn((url: string) => {
        if (url.endsWith("/api/templates")) {
          return Promise.resolve(jsonResponse({ templates: [] }));
        }
        if (url.endsWith("/api/engagements?scope=all")) {
          return Promise.resolve(jsonResponse({
            engagements: [
              { id: "eng-of02", name: "of02-dev reference", status: "observed", owner: "infrastructure", templateId: "standard-rti", activeRevision: "rev-observed-001" },
              { id: "eng-zy01", name: "ZY01", status: "planned", owner: "example_operator", templateId: "standard-rti", activeRevision: "rev-zy01-001" }
            ]
          }));
        }
        return Promise.resolve(jsonResponse({ jobs: [] }));
      })
    );

    render(<App />);

    await waitFor(() => expect(screen.getByLabelText("Active engagement")).toHaveValue("eng-of02"));
    expect(screen.getByLabelText("Active engagement")).toHaveDisplayValue("of02-dev reference");

    fireEvent.change(screen.getByLabelText("Active engagement"), {
      target: { value: "eng-zy01" }
    });

    expect(screen.getByLabelText("Active engagement")).toHaveDisplayValue("ZY01");
    expect(screen.getByRole("heading", { name: "ZY01 / Overview" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    expect(screen.getByRole("heading", { name: "ZY01 / Capabilities" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(screen.getByRole("heading", { name: "ZY01 / Infrastructure" })).toBeInTheDocument();
  });

  it("renders the operations overview and persists Housekeeping Items", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    const createObjectURL = vi.fn(() => "blob:overview-markdown");
    const revokeObjectURL = vi.fn();
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    });
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: createObjectURL
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      value: revokeObjectURL
    });
    const overviewForExport = (housekeepingItems: string) => {
      const overview = operationsOverview(housekeepingItems);
      return {
        ...overview,
        outboundChannels: overview.outboundChannels.map((channel) => ({
          ...channel,
          domain: "egress.example.com",
          purpose: "Runbook https://runbook.example.com/path"
        })),
        inboundChannels: overview.inboundChannels.map((channel) => ({
          ...channel,
          domain: "login.example.com"
        })),
        sshConfig: {
          stanza: [
            "Host homebase-zy01",
            "    HostName 146.235.219.8",
            "    User ubuntu",
            "    IdentityFile ~/.ssh/barragan_testing",
            "    IdentitiesOnly yes",
            "    ## Keep 5901 as your local listener unless it conflicts; change 59xx to your remote VNC port.",
            "    ## Your port number is (5900 + (UID - 6000) + 1)",
            "    # LocalForward 5901 127.0.0.1:59xx",
            "",
            "Host proxy01-zy01",
            "    HostName 192.168.2.11",
            "    User ubuntu",
            "    IdentityFile ~/.ssh/barragan_testing",
            "    IdentitiesOnly yes",
            "    ProxyJump homebase-zy01"
          ].join("\n"),
          downloadName: "zy01-ssh-config"
        }
      };
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations") && init?.method === "PATCH") {
        return Promise.resolve(jsonResponse({ operations: overviewForExport("Created route through edge01.") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: overviewForExport("") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    const overviewHeadings = Array.from(screen.getByLabelText("Engagement operations dashboard").querySelectorAll("h3")).map(
      (heading) => heading.textContent
    );
    expect(overviewHeadings).toEqual([
      "Red team infrastructure status",
      "Housekeeping Items",
      "Core Infrastructure",
      "Sketch Infrastructure",
      "Outbound Channels",
      "Inbound Channels",
      "SSH config",
      "Sketch SSH key",
      "Assigned Domains"
    ]);
    await waitFor(() => expect(screen.getByLabelText("Outbound Channels")).toHaveTextContent("proxy01"));
    const coreInfrastructureTable = screen.getByLabelText("Core infrastructure");
    const sketchInfrastructureTable = screen.getByLabelText("Sketch infrastructure");
    expect(coreInfrastructureTable).toHaveTextContent("homebase-zy01");
    expect(within(coreInfrastructureTable).getByText("Status")).toBeInTheDocument();
    expect(within(coreInfrastructureTable).queryByText("State")).not.toBeInTheDocument();
    expect(sketchInfrastructureTable).toHaveTextContent("middle-zy01");
    expect(Array.from(sketchInfrastructureTable.querySelectorAll(".table-header span")).map((header) => header.textContent)).toEqual([
      "Chain",
      "Role",
      "Status",
      "Hostname",
      "Public IP",
      "Provider",
      "Region",
      "Proxy"
    ]);
    expect(screen.getByLabelText("Outbound Channels")).toHaveTextContent("Pending Core Apply");
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("login.example.com");
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("External Port");
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("Internal Port");
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("proxy01-zy01");
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("Not Deployed");
    const sshConfigPanel = screen.getByLabelText("SSH config stanza");
    expect(sshConfigPanel).toHaveTextContent("Host homebase-zy01");
    expect(sshConfigPanel).toHaveTextContent("Host proxy01-zy01");
    expect(sshConfigPanel).toHaveTextContent("ProxyJump homebase-zy01");
    expect(sshConfigPanel).toHaveTextContent("LocalForward 5901 127.0.0.1:59xx");
    expect(sshConfigPanel).toHaveTextContent("Your port number is (5900 + (UID - 6000) + 1)");
    expect(sshConfigPanel).not.toHaveTextContent("User ubuntu");
    expect(sshConfigPanel).not.toHaveTextContent("IdentityFile");
    expect(sshConfigPanel).not.toHaveTextContent("IdentitiesOnly");
    expect(screen.queryByText("Connection Chain")).not.toBeInTheDocument();
    expect(screen.queryByText("Domains / Routes")).not.toBeInTheDocument();
    expect(screen.queryByText("Backflips / Tunnels")).not.toBeInTheDocument();
    expect(screen.queryByText("Targets")).not.toBeInTheDocument();
    expect(screen.queryByText("Ansible/Terraform")).not.toBeInTheDocument();
    expect(screen.queryByText("3rd Party Hosting")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Copy Markdown" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const markdown = String(writeText.mock.calls[0][0]);
    const sectionOrder = [
      "## Status Summary",
      "## Housekeeping Items",
      "## Core Infrastructure",
      "## Sketch Infrastructure",
      "## Outbound Channels",
      "## Inbound Channels",
      "## SSH config"
    ].map((section) => markdown.indexOf(section));
    expect(sectionOrder.every((index) => index >= 0)).toBe(true);
    expect(sectionOrder).toEqual([...sectionOrder].sort((left, right) => left - right));
    expect(markdown).toContain("| proxy01-zy01 | middle-zy01 | edge-zy01 | 3333 | N/A | digitalocean | egress dot example dot com | Runbook https://runbook.example.com/path | Pending Core Apply |");
    expect(markdown).toContain("| login dot example dot com | TCP | 443 | Not Deployed | middle-zy01 | proxy01 | proxy01-zy01 | SSH Backflips | 8001 | operator access | Not Ready |");
    expect(markdown).not.toContain("| egress.example.com |");
    expect(markdown).not.toContain("| login.example.com |");
    expect(markdown).toContain("https://runbook.example.com/path");
    expect(markdown).toContain("146.235.219.8");
    expect(markdown).toContain("Host homebase-zy01");
    expect(markdown).toContain("# LocalForward 5901 127.0.0.1:59xx");
    expect(markdown).not.toContain("User ubuntu");
    expect(markdown).not.toContain("IdentityFile");
    expect(markdown).not.toContain("IdentitiesOnly");
    fireEvent.click(screen.getByText("Advanced sketch SSH keys"));
    const sketchSshStanzas = screen.getByLabelText("Sketch SSH config stanzas");
    expect(sketchSshStanzas).toHaveTextContent("Host middle-zy01");
    expect(sketchSshStanzas).toHaveTextContent("ProxyJump proxy01-zy01");
    expect(sketchSshStanzas).toHaveTextContent("Host edge-zy01");
    expect(sketchSshStanzas).toHaveTextContent("ProxyJump proxy01-zy01,middle-zy01");
    expect(sketchSshStanzas).not.toHaveTextContent("ProxyJump edge-zy01");

    fireEvent.click(screen.getByRole("button", { name: "Download Markdown" }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(createObjectURL.mock.calls[0][0]).toBeInstanceOf(Blob);
    expect(anchorClick).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:overview-markdown");

    fireEvent.change(screen.getByLabelText("Housekeeping Items"), {
      target: { value: "Created route through edge01." }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/operations",
        expect.objectContaining({ method: "PATCH" })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Housekeeping Items")).toHaveValue("Created route through edge01."));
  });

  it("renders global domain buckets and triggers Namecheap sync", async () => {
    let domains = domainGroupsFixture();
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/purposes")) {
        return Promise.resolve(jsonResponse({ purposes: ["email", "rti"] }));
      }
      if (url.endsWith("/api/domains/sync/namecheap") && init?.method === "POST") {
        domains = {
          ...domains,
          waiting_to_be_used: [
            ...domains.waiting_to_be_used,
            domainSummaryFixture({
              id: "domain-fresh",
              domainName: "fresh.example",
              bucket: "waiting_to_be_used"
            })
          ]
        };
        return Promise.resolve(jsonResponse({
          job: channelJob("job-namecheap-sync", "domain_inventory_sync"),
          domainsSynced: 4,
          hostSnapshots: 4
        }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));

    const activeBucket = await screen.findByLabelText("Currently Being Used");
    const waitingBucket = screen.getByLabelText("Waiting To Be Used");
    const historicalBucket = screen.getByLabelText("Used In Past Engagements");
    expect(activeBucket).toHaveTextContent("active.example");
    expect(activeBucket).not.toHaveTextContent("Synced");
    expect(activeBucket).not.toHaveTextContent("eng-zy01");
    expect(activeBucket).toHaveTextContent("Domain");
    expect(activeBucket).toHaveTextContent("Registrar");
    expect(activeBucket).toHaveTextContent("Registration");
    expect(activeBucket).toHaveTextContent("Expiration");
    expect(activeBucket).toHaveTextContent("Health/Risk");
    expect(activeBucket).toHaveTextContent("Engagement");
    expect(activeBucket).toHaveTextContent("Purpose");
    expect(activeBucket).toHaveTextContent("rti");
    expect(activeBucket).toHaveTextContent("Notes");
    expect(activeBucket).not.toHaveTextContent("Purpose/Notes");
    expect(waitingBucket).toHaveTextContent("waiting.example");
    expect(historicalBucket).toHaveTextContent("retired.example");

    fireEvent.click(screen.getByRole("button", { name: "Sync Namecheap" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/domains/sync/namecheap",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ includeHosts: true, requestedBy: "operator" })
        })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Waiting To Be Used")).toHaveTextContent("fresh.example"));
  });

  it("manages engagement DNS records with preview before apply", async () => {
    const dnsDomain = {
      ...domainSummaryFixture({
        id: "domain-active",
        domainName: "active.example",
        bucket: "currently_being_used",
        engagement: { id: "eng-zy01", name: "ZY01" },
        purpose: "rti",
        purposeTags: ["rti"]
      }),
      dns: {
        domainId: "domain-active",
        domainName: "active.example",
        provider: "namecheap",
        source: "provider_snapshot",
        syncJobId: "job-dns-sync",
        fetchedAt: "2026-06-14T10:00:00+00:00",
        hosts: [],
        readOnly: false,
        currentFingerprint: "sha256:cached"
      }
    };
    const dnsWorkspace = {
      engagementId: "eng-zy01",
      domains: [dnsDomain],
      edgeTargets: [
        {
          id: "edge-zy01-us-sea-01",
          label: "edge-zy01-us-sea-01 (198.51.100.30)",
          chainId: "chain-1",
          hostname: "edge-zy01-us-sea-01",
          provider: "linode",
          publicIp: "198.51.100.30",
          region: "us-sea",
          proxy: "proxy01-zy01",
          status: "deployed"
        }
      ],
      supportedRecordTypes: ["A", "AAAA", "CNAME", "TXT", "MX", "NS"],
      defaultTtl: 600,
      notice: "DNS records only change registrar host records; they do not create inbound channels, proxy routes, certificates, or services."
    };
    const preview = {
      domain: dnsDomain,
      currentRecords: [],
      desiredRecords: [{ name: "@", type: "A", address: "198.51.100.30", ttl: "600", mxPref: "" }],
      diff: {
        added: [{ name: "@", type: "A", address: "198.51.100.30", ttl: "600", mxPref: "" }],
        updated: [],
        removed: [],
        unchanged: []
      },
      currentFingerprint: "sha256:preview"
    };
    const previewBodies: unknown[] = [];
    const applyBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-06-14T00:00:00+00:00",
            summary: {
              templates: 0,
              engagements: 1,
              activeEngagements: 1,
              jobRuns: 0,
              activeInfrastructure: 0,
              attention: 0,
              destroyed: 0,
              lastKnown: 0,
              orphanCandidates: 0
            },
            inventory: [],
            orphanCandidates: [],
            reconciliation: { status: "local-records", detail: "Local records." }
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns/preview") && init?.method === "POST") {
        previewBodies.push(JSON.parse(String(init.body ?? "{}")));
        return Promise.resolve(jsonResponse({ preview }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns/apply") && init?.method === "POST") {
        applyBodies.push(JSON.parse(String(init.body ?? "{}")));
        return Promise.resolve(jsonResponse({
          job: {
            ...channelJob("job-dns-apply", "engagement_dns_apply"),
            events: [
              {
                sequence: 1,
                level: "info",
                message: "engagement DNS apply started",
                data: { domainName: "active.example" }
              },
              {
                sequence: 2,
                level: "info",
                message: "Namecheap DNS setHosts completed with full desired host list",
                data: { submittedRecordCount: 1 }
              }
            ]
          },
          status: "succeeded"
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns")) {
        return Promise.resolve(jsonResponse({ dns: dnsWorkspace }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    const workspaceNav = screen.getByRole("navigation", { name: "Engagement workspace sections" });
    expect(within(workspaceNav).getAllByRole("button").map((button) => button.textContent)).toEqual([
      "Overview",
      "Infrastructure",
      "Channels",
      "Capabilities",
      "DNS",
      "Certificates",
      "History",
      "Team",
      "Settings"
    ]);

    fireEvent.click(within(workspaceNav).getByRole("button", { name: "DNS" }));
    await screen.findByLabelText("Engagement DNS domains");
    expect(screen.getByRole("heading", { name: "DNS" })).toBeInTheDocument();
    expect(screen.getByText(/do not create inbound channels/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Manage DNS" }));

    const panel = await screen.findByRole("region", { name: "DNS records for active.example" });
    fireEvent.click(within(panel).getByRole("button", { name: "Add Record" }));
    const typeSelect = within(panel).getByLabelText("DNS record type 1") as HTMLSelectElement;
    expect(Array.from(typeSelect.options).map((option) => option.value)).toEqual(["A", "AAAA", "CNAME", "TXT", "MX", "NS"]);
    expect(within(panel).getByLabelText("DNS TTL 1")).toHaveValue("600");
    expect(within(panel).queryByLabelText("DNS edge target 1")).not.toBeInTheDocument();

    const valueInput = within(panel).getByLabelText("DNS value 1") as HTMLInputElement;
    expect(valueInput.getAttribute("list")).toMatch(/^dns-value-suggestions-/);
    const suggestionList = document.getElementById(valueInput.getAttribute("list") ?? "");
    expect(suggestionList?.querySelector('option[value="198.51.100.30"]')).not.toBeNull();
    fireEvent.change(valueInput, { target: { value: "198.51.100.30" } });
    expect(valueInput).toHaveValue("198.51.100.30");
    expect(valueInput).not.toBeDisabled();

    fireEvent.click(within(panel).getByRole("button", { name: "Apply Changes" }));
    await waitFor(() => expect(screen.getByLabelText("DNS preview diff")).toHaveTextContent("198.51.100.30"));
    expect(screen.queryByLabelText("Current DNS records")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Desired DNS records")).not.toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Apply Now" }));
    await waitFor(() => expect(screen.getByLabelText("DNS job console")).toHaveTextContent("job-dns-apply"));
    await waitFor(() => expect(screen.queryByLabelText("DNS preview diff")).not.toBeInTheDocument());
    expect(screen.queryByRole("region", { name: "DNS records for active.example" })).not.toBeInTheDocument();

    expect(previewBodies).toEqual([
      {
        domainId: "domain-active",
        records: [{ name: "@", type: "A", address: "198.51.100.30", ttl: "600", mxPref: "" }],
        requestedBy: "operator"
      }
    ]);
    expect(applyBodies).toEqual([
      {
        domainId: "domain-active",
        records: [{ name: "@", type: "A", address: "198.51.100.30", ttl: "600", mxPref: "" }],
        currentFingerprint: "sha256:preview",
        requestedBy: "operator"
      }
    ]);
  });

  it("guides DNS record removal through preview before apply", async () => {
    const dnsDomain = {
      ...domainSummaryFixture({
        id: "domain-remove",
        domainName: "remove.example",
        bucket: "currently_being_used",
        engagement: { id: "eng-zy01", name: "ZY01" },
        purpose: "rti",
        purposeTags: ["rti"]
      }),
      dns: {
        domainId: "domain-remove",
        domainName: "remove.example",
        provider: "namecheap",
        source: "provider_snapshot",
        syncJobId: "job-dns-sync",
        fetchedAt: "2026-06-14T10:00:00+00:00",
        hosts: [{ name: "www", type: "A", address: "198.51.100.30", ttl: "300", mxPref: "10", hostId: "h1" }],
        readOnly: false,
        currentFingerprint: "sha256:cached"
      }
    };
    const dnsWorkspace = {
      engagementId: "eng-zy01",
      domains: [dnsDomain],
      edgeTargets: [],
      supportedRecordTypes: ["A", "AAAA", "CNAME", "TXT", "MX"],
      defaultTtl: 600,
      notice: "DNS records only change registrar host records; they do not create inbound channels, proxy routes, certificates, or services."
    };
    const preview = {
      domain: dnsDomain,
      currentRecords: [{ name: "www", type: "A", address: "198.51.100.30", ttl: "300", mxPref: "10", hostId: "h1" }],
      desiredRecords: [],
      diff: {
        added: [],
        updated: [],
        removed: [{ name: "www", type: "A", address: "198.51.100.30", ttl: "300", mxPref: "10", hostId: "h1" }],
        unchanged: []
      },
      currentFingerprint: "sha256:preview-remove"
    };
    const previewBodies: unknown[] = [];
    const applyBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-06-14T00:00:00+00:00",
            summary: {
              templates: 0,
              engagements: 1,
              activeEngagements: 1,
              jobRuns: 0,
              activeInfrastructure: 0,
              attention: 0,
              destroyed: 0,
              lastKnown: 0,
              orphanCandidates: 0
            },
            inventory: [],
            orphanCandidates: [],
            reconciliation: { status: "local-records", detail: "Local records." }
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns/preview") && init?.method === "POST") {
        previewBodies.push(JSON.parse(String(init.body ?? "{}")));
        return Promise.resolve(jsonResponse({ preview }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns/apply") && init?.method === "POST") {
        applyBodies.push(JSON.parse(String(init.body ?? "{}")));
        return Promise.resolve(jsonResponse({
          job: {
            ...channelJob("job-dns-remove", "engagement_dns_apply"),
            events: [
              { sequence: 1, level: "info", message: "engagement DNS apply started", data: { domainName: "remove.example" } },
              { sequence: 2, level: "info", message: "Namecheap DNS setHosts completed with full desired host list", data: { submittedRecordCount: 0 } }
            ]
          },
          status: "succeeded"
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns")) {
        return Promise.resolve(jsonResponse({ dns: dnsWorkspace }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    const workspaceNav = screen.getByRole("navigation", { name: "Engagement workspace sections" });
    fireEvent.click(within(workspaceNav).getByRole("button", { name: "DNS" }));
    fireEvent.click(await screen.findByRole("button", { name: "Manage DNS" }));

    const panel = await screen.findByRole("region", { name: "DNS records for remove.example" });
    expect(within(panel).getByLabelText("DNS value 1")).toHaveValue("198.51.100.30");
    fireEvent.click(within(panel).getByRole("button", { name: "Remove" }));

    expect(within(panel).queryByRole("button", { name: "Apply DNS" })).not.toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Apply Changes" }));
    await waitFor(() => expect(screen.getByLabelText("DNS preview diff")).toHaveTextContent("remove"));
    expect(screen.queryByLabelText("Current DNS records")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Desired DNS records")).not.toBeInTheDocument();
    fireEvent.click(within(panel).getByRole("button", { name: "Apply Now" }));
    await waitFor(() => expect(screen.getByLabelText("DNS job console")).toHaveTextContent("job-dns-remove"));
    await waitFor(() => expect(screen.queryByLabelText("DNS preview diff")).not.toBeInTheDocument());
    expect(screen.queryByRole("region", { name: "DNS records for remove.example" })).not.toBeInTheDocument();

    expect(previewBodies).toEqual([{ domainId: "domain-remove", records: [], requestedBy: "operator" }]);
    expect(applyBodies).toEqual([
      { domainId: "domain-remove", records: [], currentFingerprint: "sha256:preview-remove", requestedBy: "operator" }
    ]);
  });

  it("shows DNS update preview, cancels back to live values, and reopens the job log", async () => {
    const dnsDomain = {
      ...domainSummaryFixture({
        id: "domain-update",
        domainName: "update.example",
        bucket: "currently_being_used",
        engagement: { id: "eng-zy01", name: "ZY01" },
        purpose: "rti",
        purposeTags: ["rti"]
      }),
      dns: {
        domainId: "domain-update",
        domainName: "update.example",
        provider: "namecheap",
        source: "provider_snapshot",
        syncJobId: "job-dns-sync",
        fetchedAt: "2026-06-14T10:00:00+00:00",
        hosts: [{ name: "www", type: "A", address: "198.51.100.30", ttl: "300", mxPref: "", hostId: "h1" }],
        readOnly: false,
        currentFingerprint: "sha256:cached"
      }
    };
    const dnsWorkspace = {
      engagementId: "eng-zy01",
      domains: [dnsDomain],
      edgeTargets: [],
      supportedRecordTypes: ["A", "AAAA", "CNAME", "TXT", "MX"],
      defaultTtl: 600,
      notice: "DNS records only change registrar host records; they do not create inbound channels, proxy routes, certificates, or services."
    };
    const preview = {
      domain: dnsDomain,
      currentRecords: [{ name: "www", type: "A", address: "198.51.100.30", ttl: "300", mxPref: "", hostId: "h1" }],
      desiredRecords: [{ name: "www", type: "A", address: "198.51.100.31", ttl: "300", mxPref: "" }],
      diff: {
        added: [],
        updated: [
          {
            before: { name: "www", type: "A", address: "198.51.100.30", ttl: "300", mxPref: "", hostId: "h1" },
            after: { name: "www", type: "A", address: "198.51.100.31", ttl: "300", mxPref: "" }
          }
        ],
        removed: [],
        unchanged: []
      },
      currentFingerprint: "sha256:preview-update"
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-06-14T00:00:00+00:00",
            summary: {
              templates: 0,
              engagements: 1,
              activeEngagements: 1,
              jobRuns: 0,
              activeInfrastructure: 0,
              attention: 0,
              destroyed: 0,
              lastKnown: 0,
              orphanCandidates: 0
            },
            inventory: [],
            orphanCandidates: [],
            reconciliation: { status: "local-records", detail: "Local records." }
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns/preview") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ preview }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns/apply") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          job: {
            ...channelJob("job-dns-update", "engagement_dns_apply"),
            events: [
              { sequence: 1, level: "info", message: "Namecheap DNS setHosts completed with full desired host list", data: { submittedRecordCount: 1 } }
            ]
          },
          status: "succeeded"
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/dns")) {
        return Promise.resolve(jsonResponse({ dns: dnsWorkspace }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    const workspaceNav = screen.getByRole("navigation", { name: "Engagement workspace sections" });
    fireEvent.click(within(workspaceNav).getByRole("button", { name: "DNS" }));
    fireEvent.click(await screen.findByRole("button", { name: "Manage DNS" }));

    let panel = await screen.findByRole("region", { name: "DNS records for update.example" });
    fireEvent.change(within(panel).getByLabelText("DNS value 1"), { target: { value: "198.51.100.31" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Apply Changes" }));

    const previewPanel = await screen.findByLabelText("DNS preview diff");
    expect(previewPanel).toHaveTextContent("update");
    expect(previewPanel).toHaveTextContent("198.51.100.30");
    expect(previewPanel).toHaveTextContent("198.51.100.31");
    expect(previewPanel.querySelector(".dns-diff-highlight")).not.toBeNull();

    fireEvent.click(within(previewPanel).getByRole("button", { name: "Cancel" }));
    panel = await screen.findByRole("region", { name: "DNS records for update.example" });
    await waitFor(() => expect(within(panel).getByLabelText("DNS value 1")).toHaveValue("198.51.100.30"));

    fireEvent.change(within(panel).getByLabelText("DNS value 1"), { target: { value: "198.51.100.31" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Apply Changes" }));
    fireEvent.click(await screen.findByRole("button", { name: "Apply Now" }));
    const consolePanel = await screen.findByLabelText("DNS job console");
    expect(consolePanel).toHaveTextContent("job-dns-update");
    fireEvent.click(within(consolePanel).getByRole("button", { name: "Close" }));

    fireEvent.click(await screen.findByRole("button", { name: "Manage DNS" }));
    panel = await screen.findByRole("region", { name: "DNS records for update.example" });
    const logButton = within(panel).getByRole("button", { name: "Log" });
    expect(logButton.querySelector("svg")).not.toBeNull();
    fireEvent.click(logButton);
    expect(await screen.findByLabelText("DNS job console")).toHaveTextContent("job-dns-update");
  });

  it("resubmits domain assignment after confirmation is required", async () => {
    const riskyDomain = domainSummaryFixture({
      id: "domain-burned",
      domainName: "burned.example",
      bucket: "used_in_past_engagements",
      healthRisk: {
        status: "burned",
        flags: ["burned"],
        cooldownUntil: "",
        assignableOverride: false
      },
      notes: "Burned during a past engagement."
    });
    const assignedDomain = {
      ...riskyDomain,
      bucket: "currently_being_used",
      engagement: { id: "eng-zy01", name: "ZY01" },
      purpose: "rti",
      purposeTags: ["rti"],
      notes: "Reuse approved by operator.",
      assignments: [
        {
          id: 42,
          domainId: "domain-burned",
          engagementId: "eng-zy01",
          engagementName: "ZY01",
          purpose: "rti",
          purposeTags: ["rti"],
          status: "active",
          notes: "Reuse approved by operator.",
          assignedAt: "2026-06-13T12:00:00+00:00",
          releasedAt: null
        }
      ]
    };
    let domains = domainGroupsFixture({
      currently_being_used: [],
      waiting_to_be_used: [],
      used_in_past_engagements: [riskyDomain]
    });
    const assignmentBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/purposes")) {
        return Promise.resolve(jsonResponse({ purposes: ["email", "rti", "staging"] }));
      }
      if (url.endsWith("/api/domains/domain-burned/assign") && init?.method === "POST") {
        const body = JSON.parse(String(init.body ?? "{}"));
        assignmentBodies.push(body);
        if (!body.confirmationToken) {
          return Promise.resolve(errorResponse(409, {
            error: "confirmation required",
            confirmationRequired: {
              required: true,
              token: "assign-burned.example",
              reasons: ["burned domain"]
            }
          }));
        }
        domains = {
          currently_being_used: [assignedDomain],
          waiting_to_be_used: [],
          used_in_past_engagements: []
        };
        return Promise.resolve(jsonResponse({
          domain: assignedDomain,
          assignment: assignedDomain.assignments[0]
        }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("burned.example");
    fireEvent.click(screen.getByRole("button", { name: "Open burned.example details" }));
    fireEvent.click(screen.getByRole("button", { name: "Assign engagement for burned.example" }));
    fireEvent.change(screen.getByLabelText("Domain assignment engagement"), {
      target: { value: "eng-zy01" }
    });
    fireEvent.change(screen.getByLabelText("Domain assignment notes"), {
      target: { value: "Reuse approved by operator." }
    });
    fireEvent.click(screen.getByRole("button", { name: "Assign Domain" }));

    await waitFor(() => expect(screen.getByText("Assignment requires confirmation: burned domain")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Confirm Assignment" })).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Confirmation token for burned.example"), {
      target: { value: "assign-burned.example" }
    });
    expect(screen.getByRole("button", { name: "Confirm Assignment" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm Assignment" }));

    await waitFor(() => expect(screen.getByLabelText("Currently Being Used")).toHaveTextContent("burned.example"));
    expect(assignmentBodies).toEqual([
      {
        engagementId: "eng-zy01",
        purposeTags: ["rti"],
        notes: "Reuse approved by operator.",
        assignedBy: "operator"
      },
      {
        engagementId: "eng-zy01",
        purposeTags: ["rti"],
        notes: "Reuse approved by operator.",
        assignedBy: "operator",
        confirmationToken: "assign-burned.example"
      }
    ]);
  });

  it("uses comma-separated domain purpose tags during assignment", async () => {
    let domains = domainGroupsFixture({
      currently_being_used: [],
      waiting_to_be_used: [
        domainSummaryFixture({
          id: "domain-waiting",
          domainName: "waiting.example",
          bucket: "waiting_to_be_used"
        })
      ],
      used_in_past_engagements: []
    });
    const assignmentBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/purposes")) {
        return Promise.resolve(jsonResponse({ purposes: ["email", "redirector", "rti"] }));
      }
      if (url.endsWith("/api/domains/domain-waiting/assign") && init?.method === "POST") {
        const body = JSON.parse(String(init.body ?? "{}"));
        assignmentBodies.push(body);
        const purposeTags = Array.isArray(body.purposeTags) ? body.purposeTags : [];
        const assignedDomain = {
          ...domains.waiting_to_be_used[0],
          bucket: "currently_being_used",
          engagement: { id: "eng-zy01", name: "ZY01" },
          purpose: purposeTags.join(", "),
          purposeTags,
          assignments: [
            {
              id: 11,
              domainId: "domain-waiting",
              engagementId: "eng-zy01",
              engagementName: "ZY01",
              purpose: purposeTags.join(", "),
              purposeTags,
              status: "active",
              notes: "",
              assignedAt: "2026-06-14T12:00:00+00:00",
              releasedAt: null
            }
          ]
        };
        domains = {
          currently_being_used: [assignedDomain],
          waiting_to_be_used: [],
          used_in_past_engagements: []
        };
        return Promise.resolve(jsonResponse({ domain: assignedDomain, assignment: assignedDomain.assignments[0] }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("waiting.example");
    fireEvent.click(screen.getByRole("button", { name: "Open waiting.example details" }));
    fireEvent.click(screen.getByRole("button", { name: "Assign engagement for waiting.example" }));

    const assignmentPanel = screen.getByRole("region", { name: "Assign waiting.example" });
    expect(within(assignmentPanel).getByLabelText("Domain assignment engagement")).toHaveValue("");
    expect(within(assignmentPanel).getByRole("button", { name: "Assign Domain" })).toBeDisabled();
    fireEvent.change(within(assignmentPanel).getByLabelText("Domain assignment engagement"), {
      target: { value: "eng-zy01" }
    });
    expect(within(assignmentPanel).getByLabelText("Domain assignment purpose")).toHaveValue("rti");
    expect(within(assignmentPanel).queryByRole("button", { name: "Add purpose email" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Edit notes for waiting.example")).not.toBeInTheDocument();
    fireEvent.change(within(assignmentPanel).getByLabelText("Domain assignment purpose"), {
      target: { value: "email, redirector, email" }
    });
    fireEvent.click(within(assignmentPanel).getByRole("button", { name: "Assign Domain" }));

    await waitFor(() => expect(screen.getByLabelText("Currently Being Used")).toHaveTextContent("waiting.example"));
    expect(assignmentBodies).toEqual([
      {
        engagementId: "eng-zy01",
        purposeTags: ["email", "redirector"],
        notes: "",
        assignedBy: "operator"
      }
    ]);
  });

  it("saves operator catalog state from the domain detail panel", async () => {
    let domains = domainGroupsFixture({
      currently_being_used: [],
      waiting_to_be_used: [
        domainSummaryFixture({
          id: "domain-waiting",
          domainName: "waiting.example",
          bucket: "waiting_to_be_used",
          catalogState: "auto"
        })
      ],
      used_in_past_engagements: []
    });
    const patchBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/domain-waiting/catalog-state") && init?.method === "PATCH") {
        const body = JSON.parse(String(init.body ?? "{}"));
        patchBodies.push(body);
        const updatedDomain = {
          ...domains.waiting_to_be_used[0],
          bucket: "used_in_past_engagements",
          catalogState: "used_in_past_engagements",
          assignments: []
        };
        domains = {
          currently_being_used: [],
          waiting_to_be_used: [],
          used_in_past_engagements: [updatedDomain]
        };
        return Promise.resolve(jsonResponse({ domain: updatedDomain }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("waiting.example");
    fireEvent.click(screen.getByRole("button", { name: "Open waiting.example details" }));
    expect(screen.queryByRole("button", { name: "DNS Snapshot" })).not.toBeInTheDocument();
    expect(screen.getByLabelText("Risk status for waiting.example")).toHaveValue("clear");
    expect(screen.getByRole("button", { name: "Clear Changes" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Catalog state for waiting.example"), {
      target: { value: "used_in_past_engagements" }
    });
    expect(screen.getByRole("button", { name: "Clear Changes" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Clear Changes" }));
    expect(screen.getByLabelText("Catalog state for waiting.example")).toHaveValue("auto");
    expect(screen.getByRole("button", { name: "Save Changes" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Catalog state for waiting.example"), {
      target: { value: "used_in_past_engagements" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Changes" }));

    await waitFor(() => expect(screen.getByLabelText("Used In Past Engagements")).toHaveTextContent("waiting.example"));
    expect(patchBodies).toEqual([{ catalogState: "used_in_past_engagements" }]);
  });

  it("opens assignment management from the engagement detail card for assigned domains", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary(), engagementSummary({ id: "eng-tx01", name: "TX01" })] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains: domainGroupsFixture() }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("active.example");
    fireEvent.click(screen.getByRole("button", { name: "Open active.example details" }));
    fireEvent.click(screen.getByRole("button", { name: "Manage engagement assignment for active.example" }));

    const assignmentPanel = screen.getByRole("region", { name: "Assign active.example" });
    expect(within(assignmentPanel).getByRole("heading", { name: "Manage Assignment active.example" })).toBeInTheDocument();
    expect(within(assignmentPanel).getByRole("button", { name: "Change Assignment" })).toBeEnabled();
    expect(within(assignmentPanel).getByRole("button", { name: "Release Domain" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "DNS Snapshot" })).not.toBeInTheDocument();
  });

  it("changes an assigned domain and closes the assignment panel after success", async () => {
    let domains = domainGroupsFixture();
    const assignmentBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary(), engagementSummary({ id: "eng-tx01", name: "TX01" })] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/domain-active/assign") && init?.method === "POST") {
        const body = JSON.parse(String(init.body ?? "{}"));
        assignmentBodies.push(body);
        const updatedDomain = {
          ...domains.currently_being_used[0],
          engagement: { id: "eng-tx01", name: "TX01" },
          purpose: "rti",
          purposeTags: ["rti"],
          assignments: [
            {
              id: 21,
              domainId: "domain-active",
              engagementId: "eng-tx01",
              engagementName: "TX01",
              purpose: "rti",
              purposeTags: ["rti"],
              status: "active",
              notes: "",
              assignedAt: "2026-06-14T12:00:00+00:00",
              releasedAt: null
            }
          ]
        };
        domains = {
          currently_being_used: [updatedDomain],
          waiting_to_be_used: domains.waiting_to_be_used,
          used_in_past_engagements: domains.used_in_past_engagements
        };
        return Promise.resolve(jsonResponse({ domain: updatedDomain, assignment: updatedDomain.assignments[0] }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("active.example");
    fireEvent.click(screen.getByRole("button", { name: "Open active.example details" }));
    fireEvent.click(screen.getByRole("button", { name: "Manage engagement assignment for active.example" }));
    fireEvent.click(screen.getByRole("button", { name: "Change Assignment" }));

    await waitFor(() => expect(screen.queryByRole("region", { name: "Assign active.example" })).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByLabelText("Currently Being Used")).toHaveTextContent("TX01"));
    expect(assignmentBodies).toEqual([
      {
        engagementId: "eng-tx01",
        purposeTags: ["rti"],
        notes: "",
        assignedBy: "operator"
      }
    ]);
  });

  it("releases an assigned domain and closes the assignment panel after success", async () => {
    let domains = domainGroupsFixture();
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary(), engagementSummary({ id: "eng-tx01", name: "TX01" })] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/domain-active/release") && init?.method === "POST") {
        const releasedDomain = {
          ...domains.currently_being_used[0],
          bucket: "used_in_past_engagements",
          engagement: null,
          purpose: "rti",
          purposeTags: ["rti"],
          assignments: [
            {
              id: 21,
              domainId: "domain-active",
              engagementId: "eng-zy01",
              engagementName: "ZY01",
              purpose: "rti",
              purposeTags: ["rti"],
              status: "released",
              notes: "Active RTI route.",
              assignedAt: "2026-06-14T12:00:00+00:00",
              releasedAt: "2026-06-28T00:00:00+00:00"
            }
          ]
        };
        domains = {
          currently_being_used: [],
          waiting_to_be_used: domains.waiting_to_be_used,
          used_in_past_engagements: [releasedDomain, ...domains.used_in_past_engagements]
        };
        return Promise.resolve(jsonResponse({ domain: releasedDomain, releasedAssignments: releasedDomain.assignments }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("active.example");
    fireEvent.click(screen.getByRole("button", { name: "Open active.example details" }));
    fireEvent.click(screen.getByRole("button", { name: "Manage engagement assignment for active.example" }));
    fireEvent.click(screen.getByRole("button", { name: "Release Domain" }));

    await waitFor(() => expect(screen.queryByRole("region", { name: "Assign active.example" })).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByLabelText("Used In Past Engagements")).toHaveTextContent("active.example"));
  });

  it("warns before releasing an assigned domain with DNS records", async () => {
    let domains = domainGroupsFixture({
      currently_being_used: [
        domainSummaryFixture({
          id: "domain-active",
          domainName: "active.example",
          bucket: "currently_being_used",
          engagement: { id: "eng-zy01", name: "ZY01" },
          purpose: "website",
          purposeTags: ["website"],
          dnsSummary: {
            recordCount: 1,
            recordsPreview: [{ name: "@", type: "A", address: "198.51.100.30", ttl: "600" }],
            source: "provider_snapshot",
            syncJobId: "job-dns-active",
            fetchedAt: "2026-06-28T00:00:00+00:00"
          }
        })
      ]
    });
    const releaseBodies: unknown[] = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/domains/domain-active/release") && init?.method === "POST") {
        releaseBodies.push(JSON.parse(String(init.body ?? "{}")));
        const releasedDomain = {
          ...domains.currently_being_used[0],
          bucket: "used_in_past_engagements",
          engagement: null,
          assignments: [
            {
              id: 21,
              domainId: "domain-active",
              engagementId: "eng-zy01",
              engagementName: "ZY01",
              purpose: "website",
              purposeTags: ["website"],
              status: "released",
              notes: "Active DNS route.",
              assignedAt: "2026-06-14T12:00:00+00:00",
              releasedAt: "2026-06-28T00:00:00+00:00"
            }
          ]
        };
        domains = {
          currently_being_used: [],
          waiting_to_be_used: domains.waiting_to_be_used,
          used_in_past_engagements: [releasedDomain, ...domains.used_in_past_engagements]
        };
        return Promise.resolve(jsonResponse({ domain: releasedDomain, releasedAssignments: releasedDomain.assignments }));
      }
      if (url.endsWith("/api/domains")) {
        return Promise.resolve(jsonResponse({ domains }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Domains" }));
    await screen.findByText("active.example");
    fireEvent.click(screen.getByTestId("domain-row-active.example"));
    fireEvent.click(screen.getByRole("button", { name: "Manage engagement assignment for active.example" }));
    fireEvent.click(screen.getByRole("button", { name: "Release Domain" }));

    const releasePanel = screen.getByRole("region", { name: "Release active.example" });
    expect(releasePanel).toHaveTextContent("There are active DNS records set for this domain, you should remove them before releasing the domain.");
    expect(releasePanel).toHaveTextContent("A @ -> 198.51.100.30");
    expect(releaseBodies).toEqual([]);

    fireEvent.click(within(releasePanel).getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("region", { name: "Assign active.example" })).toBeInTheDocument();
    expect(releaseBodies).toEqual([]);

    fireEvent.click(screen.getByRole("button", { name: "Release Domain" }));
    fireEvent.click(screen.getByRole("button", { name: "Release Anyway" }));

    await waitFor(() => expect(screen.queryByRole("region", { name: "Release active.example" })).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByLabelText("Used In Past Engagements")).toHaveTextContent("active.example"));
    expect(releaseBodies).toEqual([{ releasedBy: "operator" }]);
  });

  it("shows engagement-scoped provider tracking findings without unmanaged teardown controls", async () => {
    const unmanagedFinding = orphanCandidateFixture({
      candidateId: "oci:compute_instance:ocid1.instance.manual",
      resourceId: "ocid1.instance.manual",
      name: "homebase-zy01",
      engagementId: "eng-zy01",
      engagementName: "ZY01",
      classification: "unmanaged_rti",
      actions: ["track", "mark_destroyed"],
      reason: "Resource matches RTI naming for this engagement, but it does not carry Barragan ownership tags."
    });
    let currentOperations = {
      ...operationsOverview(""),
      providerFindings: [unmanagedFinding]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard/orphan-candidates/actions") && init?.method === "POST") {
        currentOperations = {
          ...currentOperations,
          providerFindings: []
        };
        return Promise.resolve(
          jsonResponse({
            candidate: unmanagedFinding,
            status: "tracked",
            confirmationToken: "teardown-homebase-zy01",
            job: {
              ...channelJob("job-track-provider", "provider_orphan_track"),
              events: [
                {
                  sequence: 1,
                  level: "info",
                  message: "provider resource tracked in Barragan records",
                  data: {}
                }
              ]
            }
          })
        );
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(
          jsonResponse({
            dashboard: {
              generatedAt: "2026-06-03T12:00:00+00:00",
              summary: {
                templates: 0,
                engagements: 1,
                activeEngagements: 1,
                jobRuns: 0,
                activeInfrastructure: 0,
                attention: 0,
                destroyed: 0,
                lastKnown: 0,
                orphanCandidates: currentOperations.providerFindings.length
              },
              inventory: [],
              orphanCandidates: currentOperations.providerFindings,
              reconciliation: {
                status: "provider-reconciled",
                detail: "Provider inventory was reconciled with Barragan runtime records."
              }
            }
          })
        );
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));

    const providerTracking = await screen.findByLabelText("Provider tracking findings");
    expect(providerTracking).toHaveTextContent("homebase-zy01");
    expect(providerTracking).toHaveTextContent("does not carry Barragan ownership tags");
    expect(providerTracking).toHaveTextContent("Track");
    expect(providerTracking).toHaveTextContent("Record Destroyed Note");
    expect(providerTracking).not.toHaveTextContent("Teardown Plan");

    fireEvent.click(screen.getByRole("button", { name: "Track" }));

    await waitFor(() => expect(screen.getByText(/provider resource tracked in Barragan records/i)).toBeInTheDocument());
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/dashboard/orphan-candidates/actions",
        expect.objectContaining({
          method: "POST",
          body: expect.stringContaining("\"action\":\"track\"")
        })
      )
    );
  });

  it("shows destroyed core infrastructure as last-known inventory", async () => {
    const destroyedOperations = {
      ...operationsOverview(""),
      healthSummary: {
        ...operationsOverview("").healthSummary,
        status: "destroyed",
        activeHostCount: 0,
        detail: "Infrastructure has been torn down; rows are retained as last-known deployment history."
      },
      coreInfrastructure: operationsOverview("").coreInfrastructure.map((host) => ({
        ...host,
        status: "destroyed",
        lifecycleState: "destroyed",
        lastKnown: true,
        health: {
          status: "destroyed",
          source: "cleanup verification",
          lastCheckedAt: "2026-06-03T12:05:00+00:00",
          stale: false,
          detail: "Infrastructure has been torn down; host/IP values are last-known historical deployment data."
        }
      }))
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: destroyedOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement status report")).toHaveTextContent("0 active / 1 last-known"));
    expect(screen.getByLabelText("Engagement status report")).toHaveTextContent("destroyed");
    expect(screen.getByLabelText("Core infrastructure")).toHaveTextContent("destroyed");
    expect(screen.getByLabelText("Core infrastructure")).toHaveTextContent("homebase-zy01");
  });

  it.each(["outbound", "inbound"] as const)("shows an inbound rejection instead of a prior %s success", async (priorDirection) => {
    const base = operationsWithDeployedSketch([]);
    const operations = {
      ...base,
      outboundChannels: [{ ...operationsOverview("").outboundChannels[0], status: "Validated", validation: { ...operationsOverview("").outboundChannels[0].validation, status: "Validated" } }]
    };
    const rejection = "Inbound channel already exists or is applying; raw route conflicts on the selected edge:53/udp.";
    let inboundAttempts = 0;
    let resolveRejection: (response: ReturnType<typeof errorResponse>) => void = () => {};
    const pendingRejection = new Promise<ReturnType<typeof errorResponse>>((resolve) => { resolveRejection = resolve; });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/outbound-channels/chain-1/validate") && init?.method === "POST") {
        return Promise.resolve(jsonResponse(outboundValidateJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels") && init?.method === "POST") {
        inboundAttempts += 1;
        if (priorDirection === "inbound" && inboundAttempts === 1) {
          return Promise.resolve(jsonResponse({
            channel: { ...JSON.parse(String(init.body)), channelId: "prior-inbound-channel" },
            job: channelJob("job-prior-inbound", "inbound_channel_apply"), status: "Validated"
          }));
        }
        return pendingRejection;
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    if (priorDirection === "outbound") {
      const outbound = screen.getByRole("region", { name: "Outbound channel status summary" });
      fireEvent.click(await within(outbound).findByRole("button", { name: "Re-check" }));
      await waitFor(() => expect(outbound).toHaveTextContent("Homebase validation returned Validated."));
    }
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const submitInbound = async () => {
      fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
      const form = screen.getByRole("region", { name: "Add inbound channel" });
      await waitFor(() => expect(within(form).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));
      fireEvent.change(within(form).getByLabelText("Inbound edge"), { target: { value: (within(form).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
      fireEvent.change(within(form).getByLabelText("Inbound mode"), { target: { value: "udp-forward" } });
      fireEvent.change(within(form).getByLabelText("Inbound external port"), { target: { value: "53" } });
      fireEvent.change(within(form).getByLabelText("Inbound internal port"), { target: { value: "26056" } });
      fireEvent.change(within(form).getByLabelText("Inbound domain"), { target: { value: "dns.example.invalid" } });
      fireEvent.change(within(form).getByLabelText("Inbound purpose"), { target: { value: "Fixture DNS listener" } });
      fireEvent.click(within(form).getByRole("button", { name: "Apply" }));
    };
    if (priorDirection === "inbound") {
      await submitInbound();
      const priorConsole = await screen.findByRole("region", { name: "Channel job console" });
      await waitFor(() => expect(priorConsole).toHaveTextContent("job-prior-inbound"));
      fireEvent.click(within(priorConsole).getByRole("button", { name: "Close" }));
    }
    await submitInbound();
    const consolePanel = await screen.findByRole("region", { name: "Channel job console" });
    expect(consolePanel).toHaveTextContent("Creating, applying, and validating inbound channel.");
    expect(consolePanel).not.toHaveTextContent("job-outbound-validate");
    expect(consolePanel).not.toHaveTextContent("job-prior-inbound");
    await act(async () => { resolveRejection(errorResponse(400, { errors: [rejection] })); });
    await waitFor(() => expect(within(consolePanel).getByText(rejection)).toBeVisible());
    expect(consolePanel).not.toHaveTextContent("Completed successfully");
    expect(consolePanel).toHaveTextContent("No channel job events are available yet.");
  });

  it("adds removes and recovers inbound channels with derived edge attachment", async () => {
    const addedChannel = {
      channelId: "edge-zy01-us-sea-01-80-to-proxy01-18080",
      domain: "www.example.invalid",
      protocol: "HTTP",
      mode: "http-openresty",
      externalPort: "80",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "proxy01-zy01",
      service: "File service",
      internalPort: "18080",
      purpose: "Test web route",
      status: "Pending Validation",
      validation: {
        status: "Pending Validation",
        externalIngressVerified: false,
        detail: "Inbound route applied."
      }
    };
    let currentOperations = operationsWithDeployedSketch([]);
    let validationAttempts = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels") && init?.method === "POST") {
        currentOperations = operationsWithDeployedSketch([addedChannel]);
        return Promise.resolve(jsonResponse({ channel: addedChannel, job: channelJob("job-inbound-apply", "inbound_channel_apply"), status: "Pending Validation" }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels/edge-zy01-us-sea-01-80-to-proxy01-18080") && init?.method === "DELETE") {
        currentOperations = operationsWithDeployedSketch([{ ...addedChannel, status: "Removed", validation: { status: "Removed", detail: "Removed." } }]);
        return Promise.resolve(jsonResponse({ job: channelJob("job-inbound-remove", "inbound_channel_remove"), status: "Removed" }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels/edge-zy01-us-sea-01-80-to-proxy01-18080/recover") && init?.method === "POST") {
        currentOperations = operationsWithDeployedSketch([addedChannel]);
        return Promise.resolve(jsonResponse({ channel: addedChannel, job: channelJob("job-inbound-recover", "inbound_channel_apply"), status: "Pending Validation" }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels/edge-zy01-us-sea-01-80-to-proxy01-18080/validate") && init?.method === "POST") {
        validationAttempts += 1;
        if (validationAttempts === 1) {
          return Promise.reject(new Error("validation runner unavailable"));
        }
        const validated = {
          ...addedChannel,
          status: "Validated",
          validation: { ...addedChannel.validation, status: "Validated", detail: "Inbound route validation succeeded." }
        };
        currentOperations = operationsWithDeployedSketch([validated]);
        return Promise.resolve(jsonResponse({ job: inboundValidateJob().job, status: "Validated" }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels/edge-zy01-us-sea-01-80-to-proxy01-18080/managed-runtime")) {
        return Promise.resolve(jsonResponse({
          routeId: addedChannel.channelId,
          channelId: addedChannel.channelId,
          mode: "http-openresty",
          routingOwner: { kind: "shared-web-ingress", label: "Shared web ingress", managedBy: "Barragan" },
          selectedPath: { chainId: "chain-1", edge: addedChannel.edge, middle: addedChannel.middle, proxy: addedChannel.proxy },
          externalListener: { host: addedChannel.edge, port: "80", protocol: "TCP" },
          termination: { host: addedChannel.terminatesOn, port: "18080", service: addedChannel.service },
          site: { domain: addedChannel.domain, serviceName: "barragan-inbound-route", containerPort: "8081", backend: { kind: "private-http-service", host: addedChannel.terminatesOn, port: "18080" } },
          certificate: null,
          managedArtifacts: [{ scope: "proxy", path: "/opt/web/http/barragan-inbound-route.map" }],
          artifactStatus: "recorded",
          validation: { status: "Pending Validation", externalIngressVerified: false },
          latestJob: { id: "job-inbound-apply", action: "inbound_channel_apply", status: "succeeded" },
          failClosedDefault: { target: "127.0.0.1:9", detail: "Unmatched Host or SNI traffic fails closed." },
          readOnly: true
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    expect(screen.queryByRole("region", { name: "Channel configuration" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));
    const edgeOption = within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement;
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: edgeOption.value } });
    await waitFor(() => expect(modal).toHaveTextContent("Path: edge-zy01-us-sea-01 -> middle01-zy01 -> proxy01-zy01"));
    expect(within(modal).getByLabelText("Inbound termination")).toHaveTextContent("proxy01");
    expect(within(modal).getByLabelText("Inbound termination")).toHaveTextContent("homebase");
    expect(within(modal).getByLabelText("Inbound termination")).not.toHaveTextContent("proxy02");
    fireEvent.change(within(modal).getByLabelText("Inbound mode"), { target: { value: "http-openresty" } });
    expect(within(modal).getByLabelText("Inbound external port")).toHaveValue("80");
    fireEvent.change(within(modal).getByLabelText("Inbound backend service"), { target: { value: "File service" } });
    fireEvent.change(within(modal).getByLabelText("Inbound termination"), { target: { value: "proxy01-zy01" } });
    fireEvent.change(within(modal).getByLabelText("Inbound internal port"), { target: { value: "18080" } });
    expect(within(modal).getByRole("button", { name: "Apply" })).toBeDisabled();
    fireEvent.change(within(modal).getByLabelText("Inbound domain"), { target: { value: "www.example.invalid" } });
    fireEvent.change(within(modal).getByLabelText("Inbound purpose"), { target: { value: "Test web route" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/inbound-channels",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            chainId: "chain-1",
            edge: "edge-zy01-us-sea-01",
            edgeComponentId: "edge-chain-1",
            protocol: "HTTP",
            mode: "http-openresty",
            externalPort: "80",
            terminatesOn: "proxy01-zy01",
            internalPort: "18080",
            service: "File service",
            domain: "www.example.invalid",
            purpose: "Test web route",
            validationProfile: {
              type: "http",
              label: "HTTP route check"
            }
          })
        })
      )
    );
    let inboundSummary = screen.getByRole("region", { name: "Inbound channel status summary" });
    expect(inboundSummary).toHaveClass("responsive-channel-table");
    await waitFor(() => expect(inboundSummary).toHaveTextContent("edge-zy01-us-sea-01-80-to-proxy01-18080"));
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Route Pending Validation"));
    expect(within(inboundSummary).queryByLabelText(`Validate inbound confirmation for ${addedChannel.channelId}`)).not.toBeInTheDocument();
    fireEvent.click(within(inboundSummary).getByRole("button", { name: "Re-check" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Could not validate inbound channel from the selected edge."));
    expect(inboundSummary).toHaveTextContent("Route Pending Validation");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    inboundSummary = screen.getByRole("region", { name: "Inbound channel status summary" });
    expect(inboundSummary).toHaveTextContent("Route Pending Validation");
    fireEvent.click(within(inboundSummary).getByRole("button", { name: "Re-check" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      `/api/engagements/eng-zy01/inbound-channels/${addedChannel.channelId}/validate`,
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ confirmation: `validate-inbound-${addedChannel.channelId}` })
      })
    ));
    await waitFor(() => expect(validationAttempts).toBe(2));
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith(`/${addedChannel.channelId}/apply`))).toHaveLength(0);
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Route Validated"));
    expect(within(inboundSummary).getByText(addedChannel.channelId)).toHaveAttribute("data-label", "Channel");
    expect(within(inboundSummary).getByLabelText(`${addedChannel.channelId} validation status`).parentElement).toHaveAttribute("data-label", "Status");
    expect(within(inboundSummary).getByRole("button", { name: "Remove" }).closest("[data-label]"))
      .toHaveAttribute("data-label", "Actions");
    expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/managed-runtime"))).toBe(false);
    fireEvent.click(within(inboundSummary).getByText("Managed route details"));
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Shared web ingress"));
    expect(inboundSummary).toHaveTextContent("chain-1");
    expect(inboundSummary).toHaveTextContent(`${addedChannel.edge} → ${addedChannel.middle} → ${addedChannel.proxy}`);
    expect(inboundSummary).toHaveTextContent("127.0.0.1:9");
    expect(inboundSummary).toHaveTextContent("/opt/web/http/barragan-inbound-route.map");
    expect(inboundSummary).toHaveTextContent("job-inbound-apply · succeeded");
    expect(inboundSummary).not.toHaveTextContent("requestGateToken");
    fireEvent.click(screen.getByRole("button", { name: "Close" }));

    currentOperations = operationsWithDeployedSketch([{
      ...addedChannel,
      status: "Validation Failed",
      validation: { ...addedChannel.validation, status: "Validation Failed" }
    }]);
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    inboundSummary = screen.getByRole("region", { name: "Inbound channel status summary" });
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Route Validation Failed"));
    await waitFor(() => expect(within(inboundSummary).getByRole("button", { name: "Re-check" })).toBeInTheDocument(), { timeout: 7000 });

    currentOperations = operationsWithDeployedSketch([{
      ...addedChannel,
      status: "Pending Validation",
      validation: { ...addedChannel.validation, status: "Pending Validation" },
      validationProfile: { type: "manual", label: "Bind certificate first" }
    }]);
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    inboundSummary = screen.getByRole("region", { name: "Inbound channel status summary" });
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Route Pending Validation"));
    expect(within(inboundSummary).queryByRole("button", { name: "Re-check" })).not.toBeInTheDocument();

    currentOperations = operationsWithDeployedSketch([{
      ...addedChannel,
      status: "Validated",
      validation: { ...addedChannel.validation, status: "Validated" }
    }]);
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    inboundSummary = screen.getByRole("region", { name: "Inbound channel status summary" });
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Route Validated"));
    expect(within(inboundSummary).getByRole("button", { name: "Re-check" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(within(screen.getByRole("region", { name: "Remove inbound channel" })).getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(screen.getByRole("region", { name: "Channel job console" })).toHaveTextContent("job-inbound-remove"));
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(inboundSummary).toHaveTextContent("Removed"));
    expect(within(inboundSummary).queryByRole("button", { name: "Re-check" })).not.toBeInTheDocument();
    expect(within(inboundSummary).getByRole("button", { name: "Restore" }).closest("[data-label]"))
      .toHaveAttribute("data-label", "Actions");
    fireEvent.click(screen.getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(screen.getByRole("region", { name: "Channel job console" })).toHaveTextContent("job-inbound-recover"));
  }, 12000);

  it("shows an active request curl while enforcing the new input boundary", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    });
    const channel = {
      channelId: "edge-zy01-us-sea-01-80-to-homebase-9999",
      domain: "upload.example.invalid",
      protocol: "HTTP",
      mode: "http-openresty",
      externalPort: "80",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "homebase-zy01",
      service: "File service",
      internalPort: "9999",
      purpose: "Upload route",
      status: "Validated",
      validation: { status: "Validated" }
    };
    const activeToken = "A".repeat(20);
    const replacementToken = "manual-token-12345";
    const activeCurl = [
      "curl --include --request GET \\",
      "  --header 'Host: upload.example.invalid' \\",
      `  --header 'Authorization: Bearer ${activeToken}' \\`,
      "  'http://198.51.100.30/'"
    ].join("\n");
    const gateWorkspace = {
      channel,
      edgePublicIp: "198.51.100.30",
      gate: {
        configured: true,
        enabled: true,
        headerName: "Authorization",
        token: activeToken,
        status: "Active"
      },
      backendPolicy: {
        capabilityId: "file-service",
        authorizationManaged: true,
        maxRequestBodyMb: 500
      },
      authorizedRequest: { method: "GET", curl: activeCurl }
    };
    const rawTcpChannel = {
      ...channel,
      channelId: "edge-zy01-us-sea-01-7443-to-homebase-7443",
      domain: "",
      protocol: "TCP",
      mode: "tcp-forward",
      externalPort: "7443",
      internalPort: "7443",
      service: "Custom listener"
    };
    const pendingHttpChannel = {
      ...channel,
      channelId: "edge-zy01-us-sea-01-8080-to-homebase-9999",
      externalPort: "8080",
      status: "Applying"
    };
    const currentOperations = operationsWithDeployedSketch([channel, rawTcpChannel, pendingHttpChannel]);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`) && init?.method === "PUT") {
        return Promise.resolve(jsonResponse({
          ...gateWorkspace,
          gate: { ...gateWorkspace.gate, headerName: "X-RTI-Access" }
        }));
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`)) {
        return Promise.resolve(jsonResponse(gateWorkspace));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: currentOperations }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const summary = await screen.findByRole("region", { name: "Inbound channel status summary" });
    expect(summary.textContent?.includes(activeToken)).toBe(false);
    expect(within(summary).getAllByRole("button", { name: "Preview Reapply" })).toHaveLength(3);
    expect(within(summary).getAllByRole("button", { name: "Configure" })).toHaveLength(1);
    fireEvent.click(within(summary).getByRole("button", { name: "Configure" }));

    const panel = await screen.findByRole("region", { name: "Request header access gate" });
    await waitFor(() => expect(within(panel).getByLabelText("Enable bearer request gate")).toBeChecked());
    const tokenInput = await within(panel).findByLabelText("Request gate bearer token");
    const requestBodyInput = within(panel).getByLabelText("Maximum request body MB");
    expect(requestBodyInput).toHaveValue(500);
    expect(requestBodyInput).toHaveAttribute("max", "500");
    expect(within(panel).getByRole("region", { name: "Request size policy" })).toHaveTextContent("Default: 500 MB");
    expect(within(panel).getByRole("region", { name: "Request size policy" })).toHaveTextContent("1 MB = 1,000,000 bytes");
    expect(within(panel).getByRole("region", { name: "Request size policy" })).toHaveTextContent("Selected backend capability accepts requests up to 500 MB");
    expect(tokenInput).toHaveAttribute("maxlength", "20");
    expect((tokenInput as HTMLInputElement).value.length).toBe(20);
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeEnabled();
    expect(panel).toHaveTextContent("edge-zy01-us-sea-01 → middle01-zy01 → proxy01-zy01");
    expect(panel).toHaveTextContent("homebase-zy01:9999 · File service");
    const curlPreview = within(panel).getByRole("region", { name: "Authorized GET example" }).querySelector("pre");
    expect({ present: Boolean(curlPreview), matchesBackend: curlPreview?.textContent === activeCurl }).toEqual({ present: true, matchesBackend: true });
    fireEvent.click(within(panel).getByRole("button", { name: "Copy curl" }));
    await waitFor(() => expect(writeText.mock.calls.at(-1)?.[0] === activeCurl).toBe(true));

    fireEvent.click(within(panel).getByRole("button", { name: "Generate" }));
    const generatedToken = (tokenInput as HTMLInputElement).value;
    const rotatedPreview = within(panel).getByRole("region", { name: "Authorized GET example" }).querySelector("pre")?.textContent ?? "";
    expect({
      length: generatedToken.length,
      urlSafe: /^[A-Za-z0-9_-]+$/.test(generatedToken),
      previewUsesReplacement: rotatedPreview.includes(generatedToken),
      previewDroppedPrevious: !rotatedPreview.includes(activeToken)
    }).toEqual({ length: 20, urlSafe: true, previewUsesReplacement: true, previewDroppedPrevious: true });
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeEnabled();

    fireEvent.change(tokenInput, { target: { value: "P".repeat(21) } });
    expect((tokenInput as HTMLInputElement).value.length).toBe(21);
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeDisabled();
    fireEvent.change(tokenInput, { target: { value: "B".repeat(20) } });
    expect((tokenInput as HTMLInputElement).value.length).toBe(20);
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeEnabled();

    fireEvent.change(within(panel).getByLabelText("Request gate header name"), { target: { value: "1-Bad-Header" } });
    expect(within(panel).getByRole("alert")).toHaveTextContent("beginning with a letter");
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeDisabled();
    fireEvent.change(within(panel).getByLabelText("Request gate header name"), { target: { value: "Expect" } });
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeDisabled();
    fireEvent.change(within(panel).getByLabelText("Request gate header name"), { target: { value: "X-RTI-Access" } });
    fireEvent.change(within(panel).getByLabelText("Request gate bearer token"), { target: { value: replacementToken } });
    fireEvent.change(requestBodyInput, { target: { value: "0" } });
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeDisabled();
    expect(within(panel).getByRole("alert")).toHaveTextContent("1 through 500 MB");
    fireEvent.change(requestBodyInput, { target: { value: "750" } });
    expect(within(panel).getByRole("button", { name: "Save channel policy" })).toBeDisabled();
    fireEvent.change(requestBodyInput, { target: { value: "500" } });
    fireEvent.click(within(panel).getByRole("button", { name: "Save channel policy" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      `/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`,
      expect.objectContaining({
        method: "PUT",
        body: JSON.stringify({ enabled: true, headerName: "X-RTI-Access", tokenAction: "provide", token: replacementToken, maxRequestBodyMb: 500 })
      })
    ));
  }, 12000);

  it("resumes request-gate polling after the configuration panel is closed and reopened", async () => {
    const channel = {
      channelId: "edge-zy01-us-sea-01-80-to-homebase-9999",
      domain: "upload.example.invalid",
      protocol: "HTTP",
      mode: "http-openresty",
      externalPort: "80",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "homebase-zy01",
      service: "Go Simple Upload Server",
      internalPort: "9999",
      purpose: "Upload route",
      status: "Validated",
      validation: { status: "Validated" }
    };
    const token = "stable-token-123";
    const runningJob = {
      id: "job-gate-running",
      action: "inbound_request_header_gate_apply",
      status: "running",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", channelId: channel.channelId, proxyId: "proxy01-zy01" },
      artifactRefs: [],
      events: [{ sequence: 1, level: "info", message: "gate convergence started", data: {} }]
    };
    const activeWorkspace = {
      channel,
      gate: { configured: true, enabled: true, headerName: "Authorization", token, status: "Active" },
      authorizedRequest: { method: "GET", curl: `curl --request GET --header 'Authorization: Bearer ${token}' http://198.51.100.30/` }
    };
    const pendingWorkspace = {
      ...activeWorkspace,
      gate: { ...activeWorkspace.gate, status: "Applying" },
      pending: { state: "running", jobId: runningJob.id, message: "Request-header gate convergence is running." },
      job: runningJob
    };
    let applying = false;
    let gateGets = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs/job-gate-running")) return Promise.resolve(jsonResponse({ job: runningJob }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`) && init?.method === "PUT") {
        applying = true;
        return Promise.resolve(jsonResponse(pendingWorkspace));
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`)) {
        gateGets += 1;
        return Promise.resolve(jsonResponse(applying ? pendingWorkspace : activeWorkspace));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([channel]) }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const summary = await screen.findByRole("region", { name: "Inbound channel status summary" });
    fireEvent.click(within(summary).getByRole("button", { name: "Configure" }));
    let panel = await screen.findByRole("region", { name: "Request header access gate" });
    await waitFor(() => expect(within(panel).getByLabelText("Request gate bearer token")).toHaveValue(token));
    fireEvent.click(within(panel).getByRole("button", { name: "Save channel policy" }));
    await waitFor(() => expect(within(panel).getByRole("status")).toHaveTextContent("Request access job running"));
    fireEvent.click(within(panel).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Request header access gate" })).not.toBeInTheDocument());

    fireEvent.click(within(summary).getByRole("button", { name: "Configure" }));
    panel = await screen.findByRole("region", { name: "Request header access gate" });
    await waitFor(() => expect(within(panel).getByRole("status")).toHaveTextContent("Request access job running"));
    expect(within(panel).getByRole("button", { name: "Saving channel policy…" })).toBeDisabled();
    expect(gateGets).toBeGreaterThanOrEqual(2);
  }, 12000);

  it("shows an interrupted request-gate mutation as retryable instead of polling forever", async () => {
    const channel = {
      channelId: "edge-zy01-us-sea-01-80-to-homebase-9999",
      domain: "upload.example.invalid",
      protocol: "HTTP",
      mode: "http-openresty",
      externalPort: "80",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "homebase-zy01",
      service: "Go Simple Upload Server",
      internalPort: "9999",
      purpose: "Upload route",
      status: "Validated",
      validation: { status: "Validated" }
    };
    const token = "stable-token-123";
    const staleJob = {
      id: "job-gate-interrupted",
      action: "inbound_request_header_gate_apply",
      status: "running",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", channelId: channel.channelId, proxyId: "proxy01-zy01" },
      artifactRefs: [],
      events: [{ sequence: 1, level: "info", message: "gate convergence started", data: {} }]
    };
    const activeWorkspace = {
      channel,
      gate: { configured: true, enabled: true, headerName: "Authorization", token, status: "Active" },
      authorizedRequest: { method: "GET", curl: `curl --request GET --header 'Authorization: Bearer ${token}' http://198.51.100.30/` }
    };
    const retryWorkspace = {
      ...activeWorkspace,
      gate: { ...activeWorkspace.gate, status: "Retry required" },
      pending: {
        state: "retry-required",
        jobId: staleJob.id,
        message: "The prior request-header gate convergence was interrupted. Apply the policy again to retry safely."
      },
      job: staleJob
    };
    let recovered = false;
    let jobPolls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs/job-gate-interrupted")) {
        jobPolls += 1;
        return Promise.resolve(jsonResponse({ job: staleJob }));
      }
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`) && init?.method === "PUT") {
        recovered = true;
        return Promise.resolve(jsonResponse(activeWorkspace));
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`)) {
        return Promise.resolve(jsonResponse(recovered ? activeWorkspace : retryWorkspace));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([channel]) }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const summary = await screen.findByRole("region", { name: "Inbound channel status summary" });
    fireEvent.click(within(summary).getByRole("button", { name: "Configure" }));
    const panel = await screen.findByRole("region", { name: "Request header access gate" });
    await waitFor(() => expect(within(panel).getByRole("status")).toHaveTextContent("interrupted"));
    expect(within(panel).getByLabelText("Request gate bearer token")).toHaveValue(token);
    expect(within(panel).getByRole("button", { name: "Retry channel policy" })).toBeEnabled();
    expect(jobPolls).toBe(0);
    fireEvent.click(within(panel).getByRole("button", { name: "Retry channel policy" }));
    await waitFor(() => expect(recovered).toBe(true));
    await waitFor(() => expect(within(panel).getByRole("status")).toHaveTextContent("active"));
    expect(jobPolls).toBe(0);
  }, 12000);

  it("keeps a failed request-gate rotation visible while restoring the retained active policy", async () => {
    const channel = {
      channelId: "edge-zy01-us-sea-01-80-to-homebase-9999",
      domain: "upload.example.invalid",
      protocol: "HTTP",
      mode: "http-openresty",
      externalPort: "80",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "homebase-zy01",
      service: "Go Simple Upload Server",
      internalPort: "9999",
      purpose: "Upload route",
      status: "Validated",
      validation: { status: "Validated" }
    };
    const token = "active-token-123";
    const workspace = {
      channel,
      gate: { configured: true, enabled: true, headerName: "Authorization", token, status: "Active" },
      authorizedRequest: { method: "GET", curl: `curl --request GET --header 'Authorization: Bearer ${token}' http://198.51.100.30/` }
    };
    const runningJob = {
      id: "job-gate-failed",
      action: "inbound_request_header_gate_apply",
      status: "running",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", channelId: channel.channelId },
      artifactRefs: [],
      events: [{ sequence: 1, level: "info", message: "gate convergence started", data: {} }]
    };
    const failedJob = {
      ...runningJob,
      status: "failed",
      events: [...runningJob.events, { sequence: 2, level: "error", message: "gate convergence failed; retained active policy was preserved", data: {} }]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs/job-gate-failed")) return Promise.resolve(jsonResponse({ job: failedJob }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`) && init?.method === "PUT") {
        return Promise.resolve(jsonResponse({ ...workspace, gate: { ...workspace.gate, status: "Applying" }, job: runningJob }));
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/request-header-gate`)) return Promise.resolve(jsonResponse(workspace));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([channel]) }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const summary = await screen.findByRole("region", { name: "Inbound channel status summary" });
    fireEvent.click(within(summary).getByRole("button", { name: "Configure" }));
    const panel = await screen.findByRole("region", { name: "Request header access gate" });
    await waitFor(() => expect(within(panel).getByLabelText("Request gate bearer token")).toHaveValue(token));
    fireEvent.click(within(panel).getByRole("button", { name: "Save channel policy" }));

    await waitFor(() => expect(within(panel).getByRole("status")).toHaveTextContent("failed"), { timeout: 5000 });
    expect(within(panel).getByRole("status")).toHaveTextContent("retained active policy was preserved");
    expect(within(panel).getByLabelText("Request gate bearer token")).toHaveValue(token);
  }, 12000);

  it("opens the SSL TLS certificate manager for HTTPS inbound channels", async () => {
    const httpsChannel = {
      channelId: "edge-zy01-us-sea-01-443-to-proxy01-18080",
      domain: "secure.example.com",
      protocol: "HTTPS",
      mode: "https-openresty",
      externalPort: "443",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "proxy01-zy01",
      service: "Static Web",
      serviceId: "web-static-secure",
      serviceType: "web-static",
      internalPort: "18080",
      purpose: "campaign HTTPS site",
      status: "Validated",
      validation: {
        status: "Validated",
        externalIngressVerified: true,
        detail: "Inbound route validated."
      }
    };
    let currentOperations = operationsWithDeployedSketch([httpsChannel]);
    const certificateWorkspace = {
      channel: httpsChannel,
      certificate: {},
      prerequisites: {
        status: "ready",
        ready: true,
        summary: "Ready to request a Let's Encrypt certificate with DNS-01.",
        checkedAt: "2026-06-28T12:00:00+00:00",
        domainAssetId: "domain-secure-example-com",
        challengeType: "dns-01",
        dnsZone: "example.com",
        checks: [
          { id: "https-channel", label: "HTTPS inbound channel", status: "ready", detail: "Ready." },
          { id: "domain-present", label: "Channel domain", status: "ready", detail: "Ready." },
          { id: "domain-assigned", label: "Engagement domain assignment", status: "ready", detail: "Ready." },
          { id: "dns01-provider", label: "DNS-01 provider access", status: "ready", detail: "Barragan can update the assigned Namecheap zone." }
        ]
      }
    };
    let certificateWorkspaceCalls = 0;
    let operationsCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${httpsChannel.channelId}/certificate-binding`) && (!init?.method || init.method === "GET")) {
        certificateWorkspaceCalls += 1;
        return Promise.resolve(jsonResponse({ channel: httpsChannel, certificate: null, binding: null, candidates: [], routeStatus: httpsChannel.status, tlsStatus: "unbound" }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        operationsCalls += 1;
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    await waitFor(() => expect(screen.getByRole("region", { name: "Inbound channel status summary" })).toHaveTextContent(httpsChannel.channelId));
    fireEvent.click(screen.getByRole("button", { name: "Manage Cert" }));

    const modal = await screen.findByRole("region", { name: "SSL/TLS Cert Manager" });
    expect(modal).toHaveTextContent("Certificate binding");
    expect(modal).toHaveTextContent("TLS Unbound");
    expect(modal).toHaveTextContent("Certificate authoring and lifecycle actions live in the engagement Certificates workspace");
    expect(within(modal).getByRole("button", { name: "Bind certificate" })).toBeDisabled();
    expect(within(modal).getByRole("button", { name: "Open Certificates" })).toBeEnabled();
    expect(certificateWorkspaceCalls).toBe(1);
    expect(operationsCalls).toBeGreaterThan(0);
  }, 12000);

  it("binds an explicitly selected covering certificate", async () => {
    const fixture = certificateManagerTestFixture({ issueStatus: "running", pollStatus: "succeeded" });
    vi.stubGlobal("fetch", fixture.fetchMock);

    render(<App />);

    const modal = await openReadyCertificateManager();
    fireEvent.change(within(modal).getByLabelText("Covering certificate"), { target: { value: "cert-secure" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Bind certificate" }));
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      `/api/engagements/eng-zy01/inbound-channels/${fixture.channel.channelId}/certificate-binding`,
      expect.objectContaining({ method: "PATCH", body: JSON.stringify({ certificateId: "cert-secure" }) })
    ));
    const consolePanel = await screen.findByRole("region", { name: "Certificate job console" });
    expect(consolePanel).toHaveTextContent("certificate_asset_bind");
    expect(within(consolePanel).getByRole("button", { name: "Copy log" })).toBeEnabled();
    fireEvent.click(within(consolePanel).getByRole("button", { name: "Close" }));
    expect(within(modal).getByRole("button", { name: "Log" })).toBeEnabled();
  }, 12000);

  it("routes certificate authoring to the engagement Certificates workspace", async () => {
    const fixture = certificateManagerTestFixture({ issueStatus: "succeeded" });
    vi.stubGlobal("fetch", fixture.fetchMock);

    render(<App />);

    const modal = await openReadyCertificateManager();
    fireEvent.click(within(modal).getByRole("button", { name: "Open Certificates" }));
    expect(await screen.findByRole("heading", { name: "Certificate Manager" })).toBeInTheDocument();
    expect(screen.getByText(/Issue and track engagement certificate assets/)).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /CN \/ SANs Source Not Before Expiration Edge Proxy Status Bindings Notes/ })).toBeInTheDocument();
    expect(screen.getByRole("row", { name: /secure.example.com, \*\.example.com Let's Encrypt/ })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "ACME profile" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Create certificate asset" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("row", { name: /secure.example.com, \*\.example.com Let's Encrypt/ }));
    const detailPanel = await screen.findByLabelText("Certificate details for Secure wildcard");
    const overviewSection = within(detailPanel).getByRole("region", { name: "Certificate overview" });
    expect(overviewSection).toHaveTextContent("Requested");
    expect(overviewSection).toHaveTextContent("Renewal count");
    const bindingSection = within(detailPanel).getByRole("region", { name: "Certificate binding" });
    expect(bindingSection).toHaveTextContent("proxy01-zy01");
    expect(bindingSection).toHaveTextContent("edge-zy01-us-sea-01-443-to-proxy01-18080");
    const identitySection = within(detailPanel).getByRole("region", { name: "Certificate identity" });
    expect(identitySection).toHaveTextContent("CN=R11,O=Let's Encrypt,C=US");
    expect(identitySection).toHaveTextContent("abc123");
    expect(identitySection).toHaveTextContent("f".repeat(64));
    expect(detailPanel).toHaveTextContent("fullchain");
    expect(detailPanel).toHaveTextContent("Renew refreshes expiration");
    expect(within(detailPanel).getByRole("button", { name: "Renew certificate" })).toHaveAttribute("title", "Refresh expiration; keep existing private key.");
    expect(within(detailPanel).getByRole("button", { name: "Reissue with new key" })).toHaveAttribute("title", "Rotate private key and request replacement certificate.");
    fireEvent.change(within(detailPanel).getByLabelText("Edit certificate notes"), { target: { value: "Updated cert purpose" } });
    fireEvent.click(within(detailPanel).getByRole("button", { name: "Save Notes" }));
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/certificates/cert-secure",
      expect.objectContaining({ method: "PATCH", body: JSON.stringify({ notes: "Updated cert purpose" }) })
    ));

    fireEvent.click(within(detailPanel).getByRole("button", { name: "Close" }));
    fireEvent.click(screen.getByRole("button", { name: "Configure Defaults" }));
    const defaultsPanel = await screen.findByLabelText("Let's Encrypt Defaults");
    expect(defaultsPanel).toHaveTextContent("production certificates");
    expect(within(defaultsPanel).queryByLabelText("Default ACME environment")).not.toBeInTheDocument();
    fireEvent.click(within(defaultsPanel).getByRole("button", { name: "Close" }));

    fireEvent.click(screen.getByRole("button", { name: "New Certificate" }));
    const newPanel = await screen.findByLabelText("New Certificate");
    fireEvent.change(within(newPanel).getByLabelText("Certificate name"), { target: { value: "New wildcard" } });
    fireEvent.change(within(newPanel).getByLabelText("Certificate DNS identifiers"), { target: { value: "new.example.com\n*.new.example.com" } });
    fireEvent.change(within(newPanel).getByLabelText("Certificate notes"), { target: { value: "New app cert" } });
    fireEvent.click(within(newPanel).getByRole("button", { name: "Create and Issue Certificate" }));
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/certificates",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ name: "New wildcard", source: "letsencrypt", targetProxyId: "proxy01-zy01", identifiers: ["new.example.com", "*.new.example.com"], notes: "New app cert" }) })
    ));
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/certificates/cert-new/issue",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ requestedBy: "operator", acmeEnvironment: "production" }) })
    ));
    expect(await screen.findByLabelText("Certificate Manager job console")).toHaveTextContent("certificate asset issuance succeeded");
  }, 12000);

  it("continues polling Certificate Manager jobs through repeated running responses", async () => {
    const fixture = certificateManagerTestFixture({
      issueStatus: "succeeded",
      assetIssueStatus: "running",
      assetPollStatuses: ["running", "running", "succeeded"]
    });
    vi.stubGlobal("fetch", fixture.fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Certificates" }));
    await screen.findByRole("heading", { name: "Certificate Manager" });
    fireEvent.click(screen.getByRole("button", { name: "New Certificate" }));
    const newPanel = await screen.findByLabelText("New Certificate");
    fireEvent.change(within(newPanel).getByLabelText("Certificate name"), { target: { value: "Polling proof" } });
    fireEvent.change(within(newPanel).getByLabelText("Certificate DNS identifiers"), { target: { value: "polling.example.com" } });
    fireEvent.click(within(newPanel).getByRole("button", { name: "Create and Issue Certificate" }));

    const consolePanel = await screen.findByLabelText("Certificate Manager job console");
    expect(consolePanel).toHaveTextContent("Current task");
    await waitFor(() => expect(fixture.assetJobDetailCalls()).toBe(3), { timeout: 6000 });
    await waitFor(() => {
      expect(consolePanel).toHaveTextContent("Outcome");
      expect(consolePanel).toHaveTextContent("succeeded");
      expect(consolePanel).not.toHaveTextContent("Current task");
    });
  }, 12000);

  it("requires and submits production confirmation for certificate lifecycle actions", async () => {
    const fixture = certificateManagerTestFixture({ issueStatus: "succeeded" });
    vi.stubGlobal("fetch", fixture.fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Certificates" }));
    await screen.findByRole("heading", { name: "Certificate Manager" });
    fireEvent.click(screen.getByRole("row", { name: /secure.example.com, \*\.example.com Let's Encrypt/ }));
    const detailPanel = await screen.findByLabelText("Certificate details for Secure wildcard");

    fireEvent.click(within(detailPanel).getByRole("button", { name: "Renew certificate" }));
    const renewGroup = within(detailPanel).getByRole("group", { name: "Production certificate renew confirmation" });
    const renewInput = within(renewGroup).getByLabelText("Production certificate renew phrase");
    const renewButton = within(renewGroup).getByRole("button", { name: "Confirm Renew certificate" });
    expect(renewButton).toBeDisabled();
    fireEvent.change(renewInput, { target: { value: "wrong" } });
    expect(within(renewGroup).getByRole("alert")).toHaveTextContent("Confirmation does not match");
    expect(renewButton).toBeDisabled();
    fireEvent.change(renewInput, { target: { value: "renew-token" } });
    fireEvent.click(renewButton);
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/certificates/cert-secure/renew",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ requestedBy: "operator", acmeEnvironment: "production", productionConfirmation: "renew-token" }) })
    ));
    fireEvent.click(within(await screen.findByLabelText("Certificate Manager job console")).getByRole("button", { name: "Close" }));

    fireEvent.click(within(detailPanel).getByRole("button", { name: "Reissue with new key" }));
    const reissueGroup = within(detailPanel).getByRole("group", { name: "Production certificate reissue confirmation" });
    fireEvent.change(within(reissueGroup).getByLabelText("Production certificate reissue phrase"), { target: { value: "reissue-token" } });
    fireEvent.click(within(reissueGroup).getByRole("button", { name: "Confirm Reissue with new key" }));
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/certificates/cert-secure/reissue",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ requestedBy: "operator", acmeEnvironment: "production", productionConfirmation: "reissue-token" }) })
    ));
    fireEvent.click(within(await screen.findByLabelText("Certificate Manager job console")).getByRole("button", { name: "Close" }));

    fireEvent.click(within(detailPanel).getByRole("button", { name: "Revoke" }));
    const revokeGroup = within(detailPanel).getByRole("group", { name: "Production certificate revoke confirmation" });
    fireEvent.change(within(revokeGroup).getByLabelText("Production certificate revoke phrase"), { target: { value: "revoke-token" } });
    fireEvent.click(within(revokeGroup).getByRole("button", { name: "Confirm Revoke certificate" }));
    await waitFor(() => expect(fixture.fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/certificates/cert-secure/revoke",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ requestedBy: "operator", acmeEnvironment: "production", productionConfirmation: "revoke-token" }) })
    ));
  }, 12000);

  it("ignores a late certificate workspace response from a previously selected channel", async () => {
    const fixture = certificateManagerTestFixture({ issueStatus: "succeeded" });
    const channelA = fixture.channel;
    const channelB = {
      ...channelA,
      channelId: "edge-zy01-us-sea-02-443-to-proxy01-18081",
      domain: "second.example.com",
      edge: "edge-zy01-us-sea-02",
      internalPort: "18081",
      serviceId: "web-static-second"
    };
    const resolveChannelA: { current: null | (() => void) } = { current: null };
    const readyPrerequisites = {
      status: "ready",
      ready: true,
      summary: "Ready to request a Let's Encrypt certificate.",
      checkedAt: "2026-06-29T12:00:00+00:00",
      checks: [
        { id: "domain-present", label: "Channel domain", status: "ready", detail: "Ready." },
        { id: "domain-assigned", label: "Engagement domain assignment", status: "ready", detail: "Ready." },
        { id: "dns01-provider", label: "DNS-01 provider access", status: "ready", detail: "Ready." }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([channelA, channelB]) }));
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channelA.channelId}/certificate-binding`) && (!init?.method || init.method === "GET")) {
        return new Promise((resolve) => {
          resolveChannelA.current = () => resolve(jsonResponse({
            channel: channelA, certificate: null, binding: null, candidates: [], routeStatus: channelA.status, tlsStatus: "unbound"
          }));
        });
      }
      if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channelB.channelId}/certificate-binding`) && (!init?.method || init.method === "GET")) {
        return Promise.resolve(jsonResponse({
          channel: channelB, certificate: null, binding: null, candidates: [], routeStatus: channelB.status, tlsStatus: "unbound"
        }));
      }
      return fixture.fetchMock(input, init);
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const manageButtons = await screen.findAllByRole("button", { name: "Manage Cert" });
    fireEvent.click(manageButtons[0]);
    fireEvent.click(manageButtons[1]);

    const modal = await screen.findByRole("region", { name: "SSL/TLS Cert Manager" });
    await waitFor(() => expect(modal).toHaveTextContent(channelB.channelId));
    expect(modal).toHaveTextContent(channelB.domain);
    resolveChannelA.current?.();
    await waitFor(() => expect(modal).toHaveTextContent(channelB.channelId));
    expect(modal).toHaveTextContent(channelB.domain);
    expect(modal).not.toHaveTextContent(channelA.domain);
  }, 12000);

  it("blocks generic SSH Backflips 2222 proxy self-routes in the inbound composer", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels") && init?.method === "POST") {
        return Promise.reject(new Error("blocked route should not be submitted"));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([]) }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));

    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
    fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: "2222" } });
    fireEvent.change(within(modal).getByLabelText("Inbound internal port"), { target: { value: "2222" } });
    fireEvent.change(within(modal).getByLabelText("Inbound purpose"), { target: { value: "ssh backflips" } });

    await waitFor(() => expect(within(modal).getByRole("alert")).toHaveTextContent("SSH Backflips owns proxy01-zy01:2222"));
    expect(within(modal).getByRole("alert")).toHaveTextContent("SSH Backflips capability configuration");
    expect(within(modal).getByRole("button", { name: "Apply" })).toBeDisabled();
    expect(
      fetchMock.mock.calls.some(
        ([input, init]) => String(input).endsWith("/api/engagements/eng-zy01/inbound-channels") && init?.method === "POST"
      )
    ).toBe(false);
  });

  it("keeps duplicate edge hostnames distinct and previews the exact second component", async () => {
    const operations = operationsWithDeployedSketch([]);
    const renamedEngagement = { ...engagementSummary(), name: "RENAMED" };
    const sharedHostname = "edge-shared-zy01";
    operations.sketchInfrastructure[1].hostname = sharedHostname;
    operations.sketchInfrastructure[3].hostname = sharedHostname;
    operations.sketchInfrastructure = [...operations.sketchInfrastructure].reverse();
    const previewBodies: Array<Record<string, unknown>> = [];
    const prepareBodies: Array<Record<string, unknown>> = [];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [renamedEngagement] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channel-batches/preview") && init?.method === "POST") {
        const request = JSON.parse(String(init.body));
        previewBodies.push(request);
        return Promise.resolve(jsonResponse({
          submissionId: request.submissionId,
          previewFingerprint: "b".repeat(64),
          channels: request.channels.map((channel: Record<string, string>) => ({ ...channel, channelId: "channel-exact" })),
          applyOrder: ["channel-exact"], warnings: [], status: "ready",
          summary: "1 inbound channel passed whole-batch preflight."
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels/prepare") && init?.method === "POST") {
        const request = JSON.parse(String(init.body));
        prepareBodies.push(request);
        const channel = {
          ...request.channel, channelId: "channel-exact", status: "Pending Apply",
          validation: { status: "Pending Apply", detail: "Saved for review. No infrastructure changes have run." },
        };
        operations.inboundChannels = [channel];
        return Promise.resolve(jsonResponse({
          channel, status: "Pending Apply", job: channelJob("job-prepare", "inbound_channel_prepare"),
        }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    const edgeOptions = await within(modal).findAllByRole("option", { name: /edge-shared-zy01/ });
    expect(edgeOptions).toHaveLength(2);
    expect(edgeOptions.map((option) => option.textContent)).toEqual(expect.arrayContaining([
      expect.stringContaining("proxy01"), expect.stringContaining("proxy02")
    ]));
    const second = edgeOptions.find((option) => option.textContent?.includes("proxy02")) as HTMLOptionElement;
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: second.value } });
    expect(within(modal).getByLabelText("Inbound edge")).toHaveValue(JSON.stringify(["chain-2", "edge-chain-2"]));
    expect(modal).toHaveTextContent("Path: edge-shared-zy01 -> middle02-zy01 -> proxy02-zy01");
    expect(within(modal).getByLabelText("Inbound public ingress policy")).toHaveTextContent("198.51.100.50");
    fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: "8443" } });
    fireEvent.change(within(modal).getByLabelText("Inbound backend service"), { target: { value: "fixture" } });
    fireEvent.change(within(modal).getByLabelText("Inbound internal port"), { target: { value: "18443" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Add another" }));
    fireEvent.click(within(modal).getByRole("button", { name: "Review 1 channels" }));
    await waitFor(() => expect(previewBodies).toHaveLength(1));
    expect(previewBodies[0].channels).toEqual([expect.objectContaining({
      chainId: "chain-2", edgeComponentId: "edge-chain-2", edge: sharedHostname,
      terminatesOn: "proxy02-zy01"
    })]);
    expect(within(modal).getByRole("button", { name: "Apply 1 channel" })).toBeInTheDocument();
    fireEvent.click(within(modal).getByRole("button", { name: "Save Pending" }));
    await waitFor(() => expect(prepareBodies).toHaveLength(1));
    expect(prepareBodies[0]).toMatchObject({
      submissionId: previewBodies[0].submissionId,
      previewFingerprint: "b".repeat(64),
      channel: { chainId: "chain-2", edgeComponentId: "edge-chain-2", edge: sharedHostname },
    });
    await waitFor(() => expect(within(modal).getByText("Saved Pending. No infrastructure changes have run.")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole("region", { name: "Inbound channel status summary" })).toHaveTextContent("channel-exact"));
    expect(screen.getByRole("button", { name: "Preview Apply" })).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).endsWith("/inbound-channel-batches") && init?.method === "POST")).toBe(false);
  });

  it("invalidates a selected edge when refresh replaces its component behind the same hostname and IP", async () => {
    const initial = operationsWithDeployedSketch([]);
    const replacement = structuredClone(initial);
    replacement.sketchInfrastructure[1].componentId = "edge-chain-1-replacement";
    let operationsReads = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        operationsReads += 1;
        return Promise.resolve(jsonResponse({ operations: operationsReads === 1 ? initial : replacement }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    let modal = screen.getByRole("region", { name: "Add inbound channel" });
    const original = await within(modal).findByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement;
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: original.value } });
    expect(modal).toHaveTextContent("Path: edge-zy01-us-sea-01 -> middle01-zy01 -> proxy01-zy01");

    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    await waitFor(() => expect(operationsReads).toBeGreaterThanOrEqual(2));
    modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByRole("button", { name: "Apply" })).toBeDisabled());
    expect(within(modal).getByLabelText("Inbound edge")).toHaveValue("");
    expect(modal).not.toHaveTextContent("Path: edge-zy01-us-sea-01 -> middle01-zy01 -> proxy01-zy01");
  });

  it.each([
    "conflicting middle", "duplicate semantic core", "malformed sketch alias", "resource FQDN",
    "homebase missing ID", "homebase mismatch", "homebase FQDN", "duplicate homebase reversed",
  ])("omits an edge with %s identity evidence", async (variant) => {
    const operations = operationsWithDeployedSketch([]);
    if (variant === "conflicting middle") {
      operations.sketchInfrastructure[0].proxy = "proxy02";
      operations.sketchInfrastructure[0].assignedProxyId = "proxy02";
    } else if (variant === "duplicate semantic core") {
      operations.coreInfrastructure.push({ ...operations.coreInfrastructure[1] });
    } else if (variant === "malformed sketch alias") {
      operations.sketchInfrastructure[0].proxy = "proxy01-other";
      operations.sketchInfrastructure[1].proxy = "proxy01-other";
    } else if (variant === "resource FQDN") {
      operations.coreInfrastructure[1].hostname = "proxy01-zy01.infra.redteam";
      operations.coreInfrastructure[1].expectedHostname = "proxy01-zy01.infra.redteam";
    } else if (variant === "homebase missing ID") {
      delete operations.coreInfrastructure[0].hostId;
    } else if (variant === "homebase mismatch") {
      operations.coreInfrastructure[0].expectedHostname = "homebase-other";
    } else if (variant === "homebase FQDN") {
      operations.coreInfrastructure[0].hostname = operations.coreInfrastructure[0].expectedHostname = "homebase-zy01.infra.redteam";
    } else {
      operations.coreInfrastructure.push({ ...operations.coreInfrastructure[0] });
      operations.coreInfrastructure.reverse();
    }
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [{ ...engagementSummary(), name: "RENAMED" }] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).queryByRole("option", { name: "edge-zy01-us-sea-01" })).not.toBeInTheDocument());
    expect(within(modal).getByRole("button", { name: "Apply" })).toBeDisabled();
  });

  it("reviews and submits multiple independent inbound channels as one batch", async () => {
    let previewAttempts = 0;
    let resolveRetry!: (response: Response) => void;
    const retryResponse = new Promise<Response>((resolve) => { resolveRetry = resolve; });
    const batchJob = {
      ...channelJob("job-inbound-batch", "inbound_channel_batch_apply"),
      status: "failed",
      input: {
        engagementId: "eng-zy01",
        children: [
          { channelId: "channel-1", status: "validated" },
          { channelId: "channel-2", status: "not_started" }
        ]
      }
    };
    const retryJob = {
      ...channelJob("job-inbound-batch-retry", "inbound_channel_batch_apply"),
      input: { engagementId: "eng-zy01", children: [{ channelId: "channel-2", status: "validated" }] }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([]) }));
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channel-batches/preview") && init?.method === "POST") {
        previewAttempts += 1;
        if (previewAttempts === 1) {
          return Promise.resolve(errorResponse(400, { errors: ["row 2: listener is already claimed"] }));
        }
        const request = JSON.parse(String(init.body));
        return Promise.resolve(jsonResponse({
          submissionId: request.submissionId,
          previewFingerprint: "a".repeat(64),
          channels: request.channels.map((channel: Record<string, string>, index: number) => ({ ...channel, channelId: `channel-${index + 1}` })),
          applyOrder: ["channel-1", "channel-2"],
          warnings: [],
          status: "ready",
          summary: "2 inbound channels passed whole-batch preflight."
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channel-batches") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ batchId: batchJob.id, channels: [], job: batchJob }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channel-batches/job-inbound-batch/retry") && init?.method === "POST") {
        return retryResponse;
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));

    const fillTcpRow = (externalPort: string) => {
      fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
      fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: externalPort } });
      fireEvent.change(within(modal).getByLabelText("Inbound internal port"), { target: { value: externalPort } });
      fireEvent.change(within(modal).getByLabelText("Inbound purpose"), { target: { value: `Listener ${externalPort}` } });
    };
    fillTcpRow("18080");
    fireEvent.click(within(modal).getByRole("button", { name: "Add another" }));
    expect(within(modal).getByLabelText("Inbound batch rows")).toHaveTextContent("18080");
    fillTcpRow("18081");
    fireEvent.click(within(modal).getByRole("button", { name: "Review 2 channels" }));

    await waitFor(() => expect(within(modal).getByText("row 2: listener is already claimed")).toBeInTheDocument());
    fireEvent.click(within(modal).getByRole("button", { name: "Review 2 channels" }));

    await waitFor(() => expect(within(modal).getByText("2 inbound channels passed whole-batch preflight.")).toBeInTheDocument());
    expect(within(modal).getByRole("status", { name: "Reviewed inbound batch" })).toHaveTextContent("edge-zy01-us-sea-01:18080");
    expect(within(modal).getByRole("status", { name: "Reviewed inbound batch" })).toHaveTextContent("Managed provider and host firewall scope");
    const apply = within(modal).getByRole("button", { name: "Apply 2 channels" });
    fireEvent.click(apply);
    fireEvent.click(apply);
    await waitFor(() => expect(screen.getByRole("region", { name: "Inbound batch progress console" })).toHaveTextContent("channel-2 — not_started"));
    expect(screen.queryByRole("region", { name: "Add inbound channel" })).not.toBeInTheDocument();
    fireEvent.click(within(screen.getByRole("region", { name: "Inbound batch progress console" })).getByRole("button", { name: "Retry unfinished" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/job-inbound-batch/retry"))).toBe(true));
    fireEvent.click(within(screen.getByRole("region", { name: "Inbound batch progress console" })).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("region", { name: "Inbound batch progress console" })).not.toBeInTheDocument();
    resolveRetry(jsonResponse({ batchId: retryJob.id, channels: [], job: retryJob }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Inbound batch progress console" })).not.toBeInTheDocument());
    const applyCalls = fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith("/api/engagements/eng-zy01/inbound-channel-batches") && init?.method === "POST");
    expect(applyCalls).toHaveLength(1);
    const submitted = JSON.parse(String(applyCalls[0][1]?.body));
    expect(submitted.previewFingerprint).toBe("a".repeat(64));
    expect(submitted.channels).toHaveLength(2);
    expect(submitted.channels.map((channel: Record<string, string>) => channel.externalPort)).toEqual(["18080", "18081"]);
  });

  it("reopens the latest persisted inbound batch after a page load", async () => {
    const persistedJob = {
      ...channelJob("job-persisted-batch", "inbound_channel_batch_apply"),
      status: "failed",
      input: { engagementId: "eng-zy01", children: [{ channelId: "channel-persisted", status: "not_started" }] }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([]) }));
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channel-batches/latest")) return Promise.resolve(jsonResponse({ job: persistedJob }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    const latest = await screen.findByRole("button", { name: "Latest batch" });
    fireEvent.click(latest);
    expect(screen.getByRole("region", { name: "Inbound batch progress console" })).toHaveTextContent("channel-persisted — not_started");
  });

  it("binds an inbound channel to a configured static web service", async () => {
    const operations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: [
        {
          hostId: "proxy01",
          hostRole: "proxy",
          service: "Static Web",
          status: "Configured",
          port: "8081",
          detail: "Static web site ff10 is configured behind the shared proxy front (site container :8081).",
          serviceId: "web-ff10",
          serviceType: "web-static",
          domain: "ff10.example.invalid",
          siteName: "ff10"
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels")) {
        return Promise.resolve(jsonResponse({ channel: {}, job: channelJob("job-web-inbound-apply", "inbound_channel_apply"), status: "Pending Validation" }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
    fireEvent.change(within(modal).getByLabelText("Inbound service"), { target: { value: "web-ff10" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/inbound-channels",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            chainId: "chain-1",
            edge: "edge-zy01-us-sea-01",
            edgeComponentId: "edge-chain-1",
            protocol: "HTTP",
            mode: "http-openresty",
            externalPort: "80",
            terminatesOn: "proxy01-zy01",
            internalPort: "80",
            service: "Static Web",
            serviceId: "web-ff10",
            serviceType: "web-static",
            domain: "ff10.example.invalid",
            purpose: "ff10 web traffic",
            validationProfile: {
              type: "http",
              label: "HTTP response"
            }
          })
        })
      )
    );
  });

  it("offers an installed GoSUS capability as an explicit managed HTTPS service", async () => {
    const operations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: [
        {
          hostId: "homebase",
          hostRole: "homebase",
          service: "Go Simple Upload Server",
          status: "Active",
          port: "9999",
          protocol: "tcp",
          purpose: "file uploads",
          serviceId: "capability-go-simple-upload-server",
          serviceType: "capability-http-backend",
          validationProfile: {
            type: "manual",
            label: "Bind TLS certificate, then validate HTTPS upload from Inspector"
          }
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels")) {
        return Promise.resolve(jsonResponse({ channel: {}, job: channelJob("job-gosus-inbound-apply", "inbound_channel_apply"), status: "Pending Validation" }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
    expect(within(modal).getByLabelText("Inbound service")).toHaveTextContent(
      "Go Simple Upload Server on homebase:9999 (managed HTTPS)"
    );
    fireEvent.change(within(modal).getByLabelText("Inbound service"), {
      target: { value: "capability-go-simple-upload-server" }
    });
    fireEvent.change(within(modal).getByLabelText("Inbound domain"), { target: { value: "files.example.invalid" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/inbound-channels",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            chainId: "chain-1",
            edge: "edge-zy01-us-sea-01",
            edgeComponentId: "edge-chain-1",
            protocol: "HTTPS",
            mode: "https-openresty",
            externalPort: "443",
            terminatesOn: "proxy01-zy01",
            internalPort: "9999",
            service: "Go Simple Upload Server",
            serviceId: "capability-go-simple-upload-server",
            serviceType: "capability-http-backend",
            domain: "files.example.invalid",
            purpose: "file uploads",
            validationProfile: {
              type: "manual",
              label: "Bind TLS certificate, then validate HTTPS upload from Inspector"
            }
          })
        })
      )
    );
  });

  it("binds an inbound channel to an active generic service", async () => {
    const operations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: [
        {
          hostId: "proxy01",
          hostRole: "core",
          service: "inventory listener",
          status: "Active",
          port: "18090",
          detail: "Operator-managed TCP service tracked on proxy01:18090.",
          serviceId: "generic-inventory",
          serviceType: "generic",
          protocol: "tcp",
          transport: "tcp",
          purpose: "inventory ingress",
          scriptPath: "/opt/tools/inventory.py",
          validationProfile: { type: "tcp-connect", label: "TCP reachability" }
        }
      ],
      inboundChannels: []
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels")) {
        return Promise.resolve(jsonResponse({ channel: {}, job: channelJob("job-generic-inbound-apply", "inbound_channel_apply"), status: "Pending Validation" }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
    fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: "8443" } });
    fireEvent.change(within(modal).getByLabelText("Inbound service"), { target: { value: "generic-inventory" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Apply" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/inbound-channels",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            chainId: "chain-1",
            edge: "edge-zy01-us-sea-01",
            edgeComponentId: "edge-chain-1",
            protocol: "TCP",
            mode: "tcp-forward",
            externalPort: "8443",
            terminatesOn: "proxy01-zy01",
            internalPort: "18090",
            service: "inventory listener",
            serviceId: "generic-inventory",
            serviceType: "generic",
            domain: "",
            purpose: "inventory ingress",
            validationProfile: { type: "tcp-connect", label: "TCP reachability" }
          })
        })
      )
    );
  });

  it("adds multiple Custom Listeners without replacing the selected listener", async () => {
    let currentOperations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: []
    };
    const savedRequests: Array<{ method: string; url: string; body: Record<string, unknown> }> = [];
    const genericServiceResponse = (body: Record<string, unknown>, index: number) => {
      const serviceId = `generic-${index}`;
      const protocol = String(body.protocol || "tcp");
      const targetHost = String(body.targetHost || "proxy01");
      const internalPort = String(body.internalPort || "");
      const service = {
        engagementId: "eng-zy01",
        serviceId,
        serviceType: "generic",
        name: String(body.name || serviceId),
        proxyId: targetHost,
        status: "Active",
        config: {
          targetHost,
          internalPort: Number(internalPort),
          protocol,
          transport: protocol === "udp" ? "udp" : "tcp",
          scriptPath: String(body.scriptPath || ""),
          purpose: String(body.purpose || ""),
          tags: Array.isArray(body.tags) ? body.tags : [],
          notes: String(body.notes || ""),
          validationProfile: body.validationProfile || { type: "tcp-connect", label: "TCP reachability" }
        }
      };
      currentOperations = {
        ...currentOperations,
        servicePlacements: [
          ...currentOperations.servicePlacements,
          {
            hostId: targetHost,
            hostRole: "core",
            service: service.name,
            status: "Active",
            port: internalPort,
            detail: `Operator-managed ${protocol.toUpperCase()} service tracked on ${targetHost}:${internalPort}.`,
            serviceId,
            serviceType: "generic",
            protocol,
            transport: protocol === "udp" ? "udp" : "tcp",
            purpose: String(body.purpose || ""),
            scriptPath: String(body.scriptPath || ""),
            tags: Array.isArray(body.tags) ? body.tags : [],
            notes: String(body.notes || ""),
            validationProfile: body.validationProfile || { type: "tcp-connect", label: "TCP reachability" }
          }
        ]
      };
      return service;
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ ...engagementSummary(), name: "RENAMED" }] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: managedCapabilityWorkspace() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/custom-listener/configurations") && init?.method === "POST") {
        const body = JSON.parse(String(init.body || "{}"));
        savedRequests.push({ method: "POST", url, body });
        return Promise.resolve(jsonResponse({ service: genericServiceResponse(body, savedRequests.length) }));
      }
      if (url.includes("/api/engagements/eng-zy01/capabilities/custom-listener/configurations/") && init?.method === "PATCH") {
        const body = JSON.parse(String(init.body || "{}"));
        savedRequests.push({ method: "PATCH", url, body });
        return Promise.resolve(jsonResponse({ service: genericServiceResponse(body, savedRequests.length) }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: "Configure Custom Listener" }));
    expect(screen.queryByLabelText("Custom Listener name")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Add Custom Listener" }));
    fireEvent.change(screen.getByLabelText("Custom Listener name"), { target: { value: "inventory listener" } });
    fireEvent.change(screen.getByLabelText("Custom Listener host"), { target: { value: "proxy01" } });
    fireEvent.change(screen.getByLabelText("Custom Listener protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Custom Listener internal port"), { target: { value: "18090" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Custom Listener" }));

    await waitFor(() => expect(screen.getByText("inventory listener")).toBeInTheDocument());
    await waitFor(() => expect(screen.queryByLabelText("Custom Listener name")).not.toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Add Custom Listener" }));
    expect(screen.getByLabelText("Custom Listener name")).toHaveValue("");
    fireEvent.change(screen.getByLabelText("Custom Listener name"), { target: { value: "udp beacon" } });
    fireEvent.change(screen.getByLabelText("Custom Listener host"), { target: { value: "proxy02" } });
    fireEvent.change(screen.getByLabelText("Custom Listener protocol"), { target: { value: "udp" } });
    fireEvent.change(screen.getByLabelText("Custom Listener internal port"), { target: { value: "18100" } });
    fireEvent.click(screen.getByRole("button", { name: "Save Custom Listener" }));

    const serviceTable = await screen.findByLabelText("Custom Listener configurations");
    await waitFor(() => expect(serviceTable).toHaveTextContent("inventory listener"));
    expect(serviceTable).toHaveTextContent("udp beacon");
    expect(savedRequests.map((request) => request.method)).toEqual(["POST", "POST"]);
    fireEvent.click(within(serviceTable).getAllByRole("button", { name: "Configure" })[0]);
    expect(screen.getByRole("button", { name: "Disable configuration" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove configuration" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Disable Listener|Remove Listener/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Publish Through Inbound Channel" }));
    const inboundModal = screen.getByRole("region", { name: "Add inbound channel" });
    expect(within(inboundModal).getByLabelText("Inbound edge")).toHaveValue(JSON.stringify(["chain-1", "edge-chain-1"]));
    expect(within(inboundModal).getByLabelText("Inbound termination")).toHaveValue("proxy01-zy01");
  });

  it("does not offer pending or removed static web placements as bindable services", async () => {
    const operations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: [
        {
          hostId: "proxy01",
          hostRole: "proxy",
          service: "Static Web",
          status: "Pending Service Apply",
          port: "18080",
          detail: "Static web site ff10 apply has not run yet.",
          serviceId: "web-ff10",
          serviceType: "web-static",
          domain: "ff10.example.invalid",
          siteName: "ff10"
        },
        {
          hostId: "proxy01",
          hostRole: "proxy",
          service: "Static Web",
          status: "Removed",
          port: "18081",
          detail: "Generated config was removed. Content remains in /opt/web/oldsite/html.",
          serviceId: "web-oldsite",
          serviceType: "web-static",
          domain: "oldsite.example.invalid",
          siteName: "oldsite"
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));

    expect(within(modal).queryByLabelText("Inbound service")).not.toBeInTheDocument();
  });

  it("sets hidden UDP relay and validation defaults from the simplified inbound form", async () => {
    let currentOperations = operationsWithDeployedSketch([]);
    let postedBody: Record<string, unknown> | null = null;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels") && init?.method === "POST") {
        postedBody = JSON.parse(String(init.body));
        const channel = {
          ...postedBody,
          channelId: "edge-zy01-us-ash-02-8053-to-proxy02-18053",
          status: "Pending Validation",
          validation: { status: "Pending Validation", detail: "Inbound route applied." }
        };
        currentOperations = operationsWithDeployedSketch([channel]);
        return Promise.resolve(jsonResponse({ channel, job: channelJob("job-inbound-udp", "inbound_channel_apply"), status: "Pending Validation" }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-ash-02"));

    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-ash-02" }) as HTMLOptionElement).value } });
    fireEvent.change(within(modal).getByLabelText("Inbound mode"), { target: { value: "udp-forward" } });
    fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: "8053" } });
    fireEvent.change(within(modal).getByLabelText("Inbound internal port"), { target: { value: "18053" } });
    fireEvent.change(within(modal).getByLabelText("Inbound domain"), { target: { value: "udp.example.invalid" } });
    fireEvent.change(within(modal).getByLabelText("Inbound purpose"), { target: { value: "UDP responder route" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(postedBody).toMatchObject({
      edge: "edge-zy01-us-ash-02",
      protocol: "UDP",
      mode: "udp-forward",
      externalPort: "8053",
      terminatesOn: "proxy02-zy01",
      internalPort: "18053",
      domain: "udp.example.invalid",
      purpose: "UDP responder route",
      validationProfile: {
        type: "udp-send-receive",
        label: "UDP send/expect",
        requestText: "PING",
        expectedResponse: "FF0000"
      }
    }));
    expect(postedBody).not.toHaveProperty("relayPort");
    expect(postedBody).not.toHaveProperty("middleRelayPort");
    expect(postedBody).not.toHaveProperty("proxyRelayPort");
  });

  it("resets stale Static Web validation when switching the inbound form to manual UDP", async () => {
    let postedBody: Record<string, unknown> | null = null;
    const currentOperations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: [
        {
          hostId: "proxy01",
          hostRole: "proxy",
          service: "Static Web",
          status: "Configured",
          port: "18080",
          detail: "Static web site ff10 is configured.",
          serviceId: "web-ff10",
          serviceType: "web-static",
          domain: "ff10.example.invalid",
          siteName: "ff10"
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/inbound-channels") && init?.method === "POST") {
        postedBody = JSON.parse(String(init.body));
        return Promise.resolve(jsonResponse({
          channel: { ...postedBody, channelId: "edge-zy01-us-ash-02-8054-to-proxy02-18054" },
          job: channelJob("job-inbound-udp", "inbound_channel_apply"),
          status: "Pending Validation"
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
    fireEvent.click(screen.getByRole("button", { name: "Add Inbound Channel" }));
    const modal = screen.getByRole("region", { name: "Add inbound channel" });
    await waitFor(() => expect(within(modal).getByLabelText("Inbound edge")).toHaveTextContent("edge-zy01-us-sea-01"));

    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-sea-01" }) as HTMLOptionElement).value } });
    fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: "8011" } });
    fireEvent.change(within(modal).getByLabelText("Inbound service"), { target: { value: "web-ff10" } });
    fireEvent.change(within(modal).getByLabelText("Inbound edge"), { target: { value: (within(modal).getByRole("option", { name: "edge-zy01-us-ash-02" }) as HTMLOptionElement).value } });
    fireEvent.change(within(modal).getByLabelText("Inbound mode"), { target: { value: "udp-forward" } });
    expect(within(modal).queryByLabelText("Inbound service")).not.toBeInTheDocument();
    fireEvent.change(within(modal).getByLabelText("Inbound external port"), { target: { value: "8054" } });
    fireEvent.change(within(modal).getByLabelText("Inbound internal port"), { target: { value: "18054" } });
    fireEvent.change(within(modal).getByLabelText("Inbound domain"), { target: { value: "wi0103-udp.example.invalid" } });
    fireEvent.change(within(modal).getByLabelText("Inbound purpose"), { target: { value: "WI-0103 UDP route" } });
    fireEvent.click(within(modal).getByRole("button", { name: "Apply" }));

    await waitFor(() => expect(postedBody).toMatchObject({
      edge: "edge-zy01-us-ash-02",
      protocol: "UDP",
      mode: "udp-forward",
      externalPort: "8054",
      terminatesOn: "proxy02-zy01",
      internalPort: "18054",
      domain: "wi0103-udp.example.invalid",
      purpose: "WI-0103 UDP route",
      validationProfile: {
        type: "udp-send-receive",
        label: "UDP send/expect",
        requestText: "PING",
        expectedResponse: "FF0000"
      }
    }));
    expect(postedBody).not.toHaveProperty("service");
  });

  it("previews, explicitly applies, and lets an operator re-check an outbound channel from Channels", async () => {
    const baseOperations = operationsOverview("");
    let currentOperations = baseOperations;
    const pendingChannel = {
      ...baseOperations.outboundChannels[0],
      status: "Pending Validation",
      validation: {
        ...baseOperations.outboundChannels[0].validation,
        status: "Pending Validation",
        detail: "Core channel config applied; homebase validation has not run yet."
      }
    };
    const validatedChannel = {
      ...pendingChannel,
      status: "Validated",
      validation: { ...pendingChannel.validation, status: "Validated", detail: "Observed expected edge public IP from homebase." }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/outbound-channels/chain-1/apply-preview") && init?.method === "POST") {
        return Promise.resolve(jsonResponse(outboundApplyPreviewJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/outbound-channels/chain-1/apply") && init?.method === "POST") {
        currentOperations = { ...baseOperations, outboundChannels: [pendingChannel] };
        return Promise.resolve(jsonResponse(outboundApplyJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/outbound-channels/chain-1/validate") && init?.method === "POST") {
        currentOperations = { ...baseOperations, outboundChannels: [validatedChannel] };
        return Promise.resolve(jsonResponse(outboundValidateJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    const summary = await screen.findByRole("region", { name: "Outbound channel status summary" });
    expect(summary).toHaveClass("responsive-channel-table");
    expect(within(summary).getByText(baseOperations.outboundChannels[0].profileName).closest("[data-label]"))
      .toHaveAttribute("data-label", "Profile");
    expect(within(summary).getByRole("button", { name: "Preview Apply" }).closest("[data-label]"))
      .toHaveAttribute("data-label", "Actions");
    expect(summary).toHaveTextContent("automatically configures and validates");
    fireEvent.click(within(summary).getByRole("button", { name: "Preview Apply" }));
    const applyInput = await screen.findByLabelText("Apply outbound confirmation for chain-1");
    fireEvent.change(applyInput, { target: { value: "apply-outbound-chain-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/outbound-channels/chain-1/apply",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ confirmation: "apply-outbound-chain-1" }) })
    ));
    expect(screen.queryByLabelText("Validate outbound confirmation for chain-1")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Re-check" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/outbound-channels/chain-1/validate",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ confirmation: "validate-outbound-chain-1" }) })
    ));
    await waitFor(() => expect(summary).toHaveTextContent("Validated"));
  });

  it("renders provider-neutral compact outbound profile labels", async () => {
    const baseOperations = operationsOverview("");
    const linodeChannel = {
      ...baseOperations.outboundChannels[0],
      chainId: "proxy01-sea-02-edge-01",
      profileName: "proxy01-sea-02-edge-01"
    };
    const digitalOceanChannel = {
      ...baseOperations.outboundChannels[0],
      chainId: "proxy01-sfo3-01",
      profileName: "proxy01-sfo3-01",
      provider: "digitalocean"
    };
    const currentOperations = {
      ...baseOperations,
      outboundChannels: [linodeChannel, digitalOceanChannel]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: currentOperations }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Channels" }));
    const summary = await screen.findByRole("region", { name: "Outbound channel status summary" });
    const profiles = Array.from(summary.querySelectorAll('[data-label="Profile"]')).map((node) => node.textContent);
    expect(profiles).toEqual(["proxy01-sea-02-01", "proxy01-sfo3-01"]);
    expect(summary).not.toHaveTextContent("proxy01-sea-02-edge-01");
  });

  it("previews and safely rotates the engagement sketch SSH key from Overview", async () => {
    let currentKey = sketchKey("SHA256:old-key");
    const rotatedKey = sketchKey("SHA256:new-key", [
      {
        privateKeyName: "zy01-sketch",
        publicKeyName: "zy01-sketch.pub",
        fingerprint: "SHA256:old-key",
        status: "retired",
        reason: "rotated",
        retiredAt: "2026-06-04T01:00:00+00:00"
      }
    ]);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key") && init?.method !== "POST") {
        return Promise.resolve(jsonResponse({ key: currentKey }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key/rotation-preview")) {
        return Promise.resolve(jsonResponse({ rotation: sketchRotationPlan(currentKey, false) }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key/rotate")) {
        expect(init?.body).toBe(JSON.stringify({ confirmation: "rotate-sketch-key" }));
        currentKey = rotatedKey;
        return Promise.resolve(
          jsonResponse({
            key: rotatedKey,
            previousFingerprint: "SHA256:old-key",
            rotation: { ...sketchRotationPlan(rotatedKey, false), status: "rotated", mutation: true, previousFingerprint: "SHA256:old-key" }
          })
        );
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByText("Advanced sketch SSH keys"));

    const rotationPanel = screen.getByLabelText("Sketch SSH key rotation");
    fireEvent.click(within(rotationPanel).getByRole("button", { name: "Preview Rotation" }));
    await waitFor(() => expect(rotationPanel).toHaveTextContent("Rotation is ready"));
    expect(rotationPanel).toHaveTextContent("SHA256:old-key");
    expect(rotationPanel).toHaveTextContent("proxy jump only");
    expect(within(rotationPanel).getByRole("button", { name: "Rotate Sketch Key" })).toBeDisabled();

    fireEvent.change(within(rotationPanel).getByLabelText("Confirmation"), {
      target: { value: "rotate-sketch-key" }
    });
    expect(within(rotationPanel).getByRole("button", { name: "Rotate Sketch Key" })).toBeEnabled();
    fireEvent.click(within(rotationPanel).getByRole("button", { name: "Rotate Sketch Key" }));

    await waitFor(() => expect(screen.getAllByText("SHA256:new-key").length).toBeGreaterThan(0));
    expect(rotationPanel).toHaveTextContent("Previous fingerprint: SHA256:old-key");
    expect(screen.getByLabelText("Retired sketch SSH keys")).toHaveTextContent("SHA256:old-key");
    expect(screen.getByLabelText("Retired sketch SSH keys")).toHaveTextContent("retired");
    expect(screen.getByLabelText("Retired sketch SSH keys")).toHaveTextContent("rotated");
    expect(screen.queryByText("BEGIN OPENSSH PRIVATE KEY")).not.toBeInTheDocument();
  });

  it("blocks sketch SSH key rotation when deployed chains require OPSEC-safe repair", async () => {
    const currentKey = sketchKey("SHA256:blocked-key");
    const blockedPlan = sketchRotationPlan(currentKey, true);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key")) {
        return Promise.resolve(jsonResponse({ key: currentKey }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key/rotation-preview")) {
        return Promise.resolve(jsonResponse({ rotation: blockedPlan }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key/rotate")) {
        return Promise.resolve(errorResponse(400, { errors: ["rotation blocked"], rotation: blockedPlan }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByText("Advanced sketch SSH keys"));

    const rotationPanel = screen.getByLabelText("Sketch SSH key rotation");
    fireEvent.click(within(rotationPanel).getByRole("button", { name: "Preview Rotation" }));

    await waitFor(() => expect(rotationPanel).toHaveTextContent("Rotation is blocked"));
    expect(rotationPanel).toHaveTextContent("SHA256:blocked-key");
    expect(rotationPanel).toHaveTextContent("proxy01-sea-01");
    expect(rotationPanel).toHaveTextContent("reprovision_or_opsec_safe_repair");
    expect(rotationPanel).toHaveTextContent("proxy to middle jump only");
    fireEvent.change(within(rotationPanel).getByLabelText("Confirmation"), {
      target: { value: "rotate-sketch-key" }
    });
    expect(within(rotationPanel).getByRole("button", { name: "Rotate Sketch Key" })).toBeDisabled();
  });

  it("previews and removes sketch SSH key material after teardown", async () => {
    const currentKey = sketchKey("SHA256:remove-key");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key/removal-preview")) {
        return Promise.resolve(jsonResponse({ removal: sketchRemovalPlan(currentKey, false) }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key") && init?.method === "DELETE") {
        expect(init?.body).toBe(JSON.stringify({ confirmation: "remove-sketch-key" }));
        return Promise.resolve(
          jsonResponse({
            removedKey: currentKey,
            removal: { ...sketchRemovalPlan(currentKey, false), status: "removed", mutation: true, currentKey: null, removedFingerprint: "SHA256:remove-key" }
          })
        );
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key")) {
        return Promise.resolve(jsonResponse({ key: currentKey }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByText("Advanced sketch SSH keys"));

    const removalPanel = screen.getByLabelText("Sketch SSH key removal");
    fireEvent.click(within(removalPanel).getByRole("button", { name: "Preview Removal" }));
    await waitFor(() => expect(removalPanel).toHaveTextContent("Removal is ready"));
    expect(removalPanel).toHaveTextContent("SHA256:remove-key");
    expect(within(removalPanel).getByRole("button", { name: "Remove Sketch Key" })).toBeDisabled();

    fireEvent.change(within(removalPanel).getByLabelText("Confirmation"), {
      target: { value: "remove-sketch-key" }
    });
    expect(within(removalPanel).getByRole("button", { name: "Remove Sketch Key" })).toBeEnabled();
    fireEvent.click(within(removalPanel).getByRole("button", { name: "Remove Sketch Key" }));

    await waitFor(() => expect(removalPanel).toHaveTextContent("Removed fingerprint: SHA256:remove-key"));
    expect(removalPanel).toHaveTextContent("Generate a new key before deploying sketch again");
    expect(screen.queryByText("BEGIN OPENSSH PRIVATE KEY")).not.toBeInTheDocument();
  });

  it("blocks sketch SSH key removal while infrastructure is still recorded", async () => {
    const currentKey = sketchKey("SHA256:active-key");
    const blockedPlan = sketchRemovalPlan(currentKey, true);
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key/removal-preview")) {
        return Promise.resolve(jsonResponse({ removal: blockedPlan }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-ssh-key")) {
        return Promise.resolve(jsonResponse({ key: currentKey }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByText("Advanced sketch SSH keys"));

    const removalPanel = screen.getByLabelText("Sketch SSH key removal");
    fireEvent.click(within(removalPanel).getByRole("button", { name: "Preview Removal" }));
    await waitFor(() => expect(removalPanel).toHaveTextContent("Removal is blocked"));
    expect(removalPanel).toHaveTextContent("proxy01-sea-01");
    expect(removalPanel).toHaveTextContent("tear_down_sketch_chain_first");
    expect(removalPanel).toHaveTextContent("proxy to middle jump only");
    fireEvent.change(within(removalPanel).getByLabelText("Confirmation"), {
      target: { value: "remove-sketch-key" }
    });
    expect(within(removalPanel).getByRole("button", { name: "Remove Sketch Key" })).toBeDisabled();
  });

  it("bootstraps SSH Backflips without duplicating listener lifecycle controls", async () => {
    let currentOperations = operationsOverview("");
    const configuredOperations = {
      ...operationsOverview(""),
      inboundChannels: [
        {
          channelId: "default-backflip",
          domain: "Not Deployed",
          protocol: "TCP",
          externalPort: "443",
          edge: "Not Deployed",
          middle: "Not Deployed",
          proxy: "proxy01",
          terminatesOn: "proxy01",
          service: "SSH Backflips",
          internalPort: "2222",
          purpose: "SSH Backflips service listener on selected proxy; edge/middle ingress routing remains separate.",
          status: "Configured"
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities") && (!init?.method || init.method === "GET")) {
        return Promise.resolve(jsonResponse({ capabilities: backflipsCapabilityWorkspace() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/backflips/apply-preview")) {
        return Promise.resolve(jsonResponse(backflipsApplyPreviewJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/backflips/apply")) {
        currentOperations = configuredOperations;
        return Promise.resolve(jsonResponse(backflipsApplyJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    expect(screen.queryByRole("region", { name: "Channel configuration" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Apply to running infrastructure" })).not.toBeInTheDocument();
    const backflipsRow = await screen.findByRole("button", { name: "Configure Backflips V2" });
    expect(backflipsRow).toHaveTextContent("proxy01: Waiting · proxy02: Ready");
    fireEvent.click(backflipsRow);
    const backflipsWorkflow = screen.getByRole("region", { name: "Backflips V2 capability workflow" });
    expect(backflipsWorkflow).toHaveTextContent("/opt/backflips/sshbackflip.py");
    expect(backflipsWorkflow).toHaveTextContent("New edges inherit");
    expect(within(backflipsWorkflow).queryByRole("button", { name: "Add Listener" })).not.toBeInTheDocument();
    expect(within(backflipsWorkflow).queryByRole("button", { name: "List Listeners" })).not.toBeInTheDocument();
    expect(within(backflipsWorkflow).queryByRole("button", { name: "Delete Listener" })).not.toBeInTheDocument();

    fireEvent.change(within(backflipsWorkflow).getByLabelText("Backflips proxy"), {
      target: { value: "proxy01" }
    });
    fireEvent.click(within(backflipsWorkflow).getByRole("button", { name: "Preview Prerequisites" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/backflips/apply-preview",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ proxyId: "proxy01" })
        })
      )
    );

    expect(within(backflipsWorkflow).getByRole("button", { name: "Apply Backflips Prerequisites" })).toBeDisabled();
    fireEvent.change(within(backflipsWorkflow).getByLabelText("Backflips confirmation"), {
      target: { value: "apply-service-backflips" }
    });
    fireEvent.click(within(backflipsWorkflow).getByRole("button", { name: "Apply Backflips Prerequisites" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/backflips/apply",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ proxyId: "proxy01", confirmation: "apply-service-backflips" })
        })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Backflips job console")).toHaveTextContent("Backflips bootstrap succeeded"));
    fireEvent.click(within(screen.getByLabelText("Backflips job console")).getByRole("button", { name: "Close" }));

    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    expect(screen.getByRole("button", { name: "Configure Backflips V2" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Desktop applications/i })).not.toBeInTheDocument();
    expect(screen.queryByText("Render Lock")).not.toBeInTheDocument();
    expect(screen.queryByText("Save Selection")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    await waitFor(() => expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("SSH Backflips"));
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("2222");
    expect(screen.getByLabelText("Inbound Channels")).toHaveTextContent("Configured");
  });

  it("saves and applies manifest-backed Desktop choices from Capabilities", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    });
    let currentWorkspace = desktopCapabilityWorkspace();
    const parentJob = capabilityApplyJob("desktop");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities") && init?.method === "PATCH") {
        currentWorkspace = desktopCapabilityWorkspace(
          JSON.parse(String(init.body ?? "{}")),
          capabilityApplyState("saved_ready")
        );
        return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/apply")) {
        currentWorkspace = {
          ...currentWorkspace,
          applyState: capabilityApplyState("applied", [{ kind: "desktop", status: "succeeded", jobId: "job-desktop-apply", detail: "Desktop applications applied." }])
        };
        return Promise.resolve(jsonResponse({
          capabilityApply: { status: "applied", applyState: currentWorkspace.applyState, job: parentJob }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    await screen.findByLabelText("Disable KeePassXC");
    fireEvent.click(screen.getByLabelText("Disable KeePassXC"));
    const applyButton = screen.getByRole("button", { name: "Apply saved changes" });
    expect(applyButton).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Save capability changes" }));
    await waitFor(() => expect(applyButton).toBeEnabled());
    fireEvent.click(applyButton);

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/apply",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({})
        })
      )
    );
    fireEvent.click(await screen.findByRole("button", { name: "Log" }));
    const capabilityConsole = await screen.findByLabelText("Capability apply console");
    await waitFor(() => expect(capabilityConsole).toHaveTextContent("Desktop Ansible apply succeeded"));
    fireEvent.click(within(capabilityConsole).getByRole("button", { name: "Copy log" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("Desktop Ansible apply succeeded")));
    fireEvent.click(within(capabilityConsole).getByRole("button", { name: "Close" }));
    expect(screen.queryByLabelText("Capability apply console")).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Desktop service workflow" })).not.toBeInTheDocument();
  });

  it("saves Homebase inference configuration without requesting IAM changes", async () => {
    let savedBody: Record<string, unknown> | null = null;
    let sourceUnavailable = true;
    const configuration = { region: "", compartmentId: "", port: 8787 };
    const base = JSON.parse(JSON.stringify(optionalRoleCapabilityWorkspace())
      .replaceAll("go-simple-upload-server", "inference-proxy")
      .replaceAll("go_simple_upload_server", "inference_proxy")
      .replaceAll("Go Simple Upload Server", "Inference Proxy"));
    let currentWorkspace = { ...base, inferenceProxy: { configuration, accessStatus: "not_verified", policyGuidance: { notes: [], documentationUrl: "" } } };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities") && init?.method === "PATCH") {
        if (sourceUnavailable) {
          sourceUnavailable = false;
          return Promise.resolve(errorResponse(400, { error: "Inference Proxy source checkout is unavailable" }));
        }
        savedBody = JSON.parse(String(init.body));
        currentWorkspace = { ...currentWorkspace, overrides: { ...base.overrides, selectedOptionals: savedBody?.selectedOptionals },
          applyState: capabilityApplyState("saved_ready"), inferenceProxy: { ...currentWorkspace.inferenceProxy, configuration: savedBody?.inferenceProxy as typeof configuration } };
        return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: /Inference Proxy/i }));
    const dialog = screen.getByRole("region", { name: "Configure Inference Proxy" });
    fireEvent.change(within(dialog).getByLabelText("OCI inference region"), { target: { value: "us-chicago-1" } });
    fireEvent.change(within(dialog).getByLabelText("Model compartment OCID"), { target: { value: "ocid1.compartment.oc1..fixture" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Select Inference Proxy" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Save capability changes" }));
    expect(await screen.findByText("Inference Proxy source checkout is unavailable")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("OCI inference region")).toHaveValue("us-chicago-1");
    expect(within(dialog).getByLabelText("Model compartment OCID")).toHaveValue("ocid1.compartment.oc1..fixture");
    expect(within(dialog).getByRole("button", { name: "Deselect Inference Proxy" })).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save capability changes" }));
    await waitFor(() => expect(savedBody).toMatchObject({
      selectedOptionals: [{ id: "inference-proxy", hostClass: "homebase" }],
      inferenceProxy: { region: "us-chicago-1", compartmentId: "ocid1.compartment.oc1..fixture", port: 8787 }
    }));
    expect(dialog).toHaveTextContent("never changes IAM policies");
    expect(dialog).toHaveTextContent("not verified by service installation");
    expect(fetchMock.mock.calls.some(([input]) => /iam|dynamic-group|policies/.test(String(input)))).toBe(false);
  });

  it("checks inference discovery without overwriting a draft changed during the request", async () => {
    const configuration = { region: "us-chicago-1", compartmentId: "ocid1.compartment.oc1..fixture", port: 8787 };
    const base = JSON.parse(JSON.stringify(optionalRoleCapabilityWorkspace())
      .split("go-simple-upload-server").join("inference-proxy")
      .split("go_simple_upload_server").join("inference_proxy")
      .split("Go Simple Upload Server").join("Inference Proxy"));
    base.overrides.selectedOptionals = [{ id: "inference-proxy", hostClass: "homebase" }];
    const workspace = { ...base, inferenceProxy: { configuration, accessStatus: "not_verified", policyGuidance: { notes: [], documentationUrl: "" } } };
    const noAccess = { configuration, status: "checked", bindingFingerprint: "a".repeat(64),
      homebaseIdentity: { coreDeploymentId: "job-current", instanceId: "ocid1.instance.oc1.us-sanjose-1.fixture" },
      observation: { checkedAt: "2026-10-30T15:00:00Z", localReady: true, discoveryStatus: "discovery_unavailable",
        lastRefreshAt: null, modelCount: 0, errorCode: "oci_not_authorized_or_not_found", inferenceVerified: false }, job: null, errors: [] };
    let finishCheck: (() => void) | undefined;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) return Promise.resolve(jsonResponse({ capabilities: workspace }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      if (url.endsWith("/capabilities/inference-proxy/status")) {
        if (init?.method === "POST") return new Promise<ReturnType<typeof jsonResponse>>((resolve) => {
          finishCheck = () => resolve(jsonResponse({ inferenceProxyStatus: { ...noAccess, observation: { ...noAccess.observation,
            discoveryStatus: "catalog_available", modelCount: 2, errorCode: null } } }));
        });
        return Promise.resolve(jsonResponse({ inferenceProxyStatus: noAccess }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: /Inference Proxy/i }));
    const panel = screen.getByRole("region", { name: "Configure Inference Proxy" });
    expect(await within(panel).findByText(/OCI reported not authorized or not found/)).toBeInTheDocument();
    const check = within(panel).getByRole("button", { name: "Check service and OCI discovery" });
    fireEvent.click(check);
    await waitFor(() => expect(finishCheck).toBeTypeOf("function"));
    fireEvent.change(within(panel).getByLabelText("Inference Proxy loopback port"), { target: { value: "8788" } });
    await act(async () => { finishCheck?.(); });
    expect(within(panel).getByLabelText("Inference Proxy loopback port")).toHaveValue(8788);
    expect(within(panel).queryByText(/Model catalog available/)).not.toBeInTheDocument();
    expect(check).toBeDisabled();
    fireEvent.change(within(panel).getByLabelText("Inference Proxy loopback port"), { target: { value: "8787" } });
    expect(await within(panel).findByText(/Model catalog available \(2 models\)/)).toBeInTheDocument();
    expect(panel).toHaveTextContent("Inference access: Not verified");
    const posts = fetchMock.mock.calls.filter(([url, init]) => String(url).endsWith("/capabilities/inference-proxy/status") && init?.method === "POST");
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0][1]?.body))).toEqual({ bindingFingerprint: "a".repeat(64) });
  });

  it("saves and reconciles selected optional roles against running core hosts", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText }
    });
    let savedSelection: Array<{ hostClass: string; id: string }> = [];
    let currentWorkspace = optionalRoleCapabilityWorkspace();
    const parentJob = capabilityApplyJob("optional");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities") && init?.method === "PATCH") {
        savedSelection = JSON.parse(String(init.body ?? "{}")).selectedOptionals ?? [];
        currentWorkspace = optionalRoleCapabilityWorkspace(savedSelection, capabilityApplyState("saved_ready"));
        return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/apply")) {
        currentWorkspace = {
          ...currentWorkspace,
          applyState: capabilityApplyState("applied", [{ kind: "optional_roles", status: "succeeded", jobId: "job-optional-apply", detail: "Optional roles applied." }])
        };
        return Promise.resolve(jsonResponse({
          capabilityApply: { status: "applied", applyState: currentWorkspace.applyState, job: parentJob }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    expect(screen.queryByText(/capability lock/i)).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: /Go Simple Upload Server/i }));
    const capabilityDialog = screen.getByRole("region", { name: "Configure Go Simple Upload Server" });
    expect(capabilityDialog).toHaveTextContent("saved capability changes");
    expect(capabilityDialog).not.toHaveTextContent(/capability lock/i);
    fireEvent.click(within(capabilityDialog).getByRole("button", { name: "Close" }));
    const applyButton = await screen.findByRole("button", { name: "Apply saved changes" });
    expect(applyButton).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Enable Go Simple Upload Server"));
    fireEvent.click(screen.getByRole("button", { name: "Save capability changes" }));
    await waitFor(() => expect(applyButton).toBeEnabled());
    fireEvent.click(applyButton);

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/capabilities/apply",
      expect.objectContaining({ method: "POST", body: JSON.stringify({}) })
    ));
    expect(savedSelection).toEqual([{ hostClass: "homebase", id: "go-simple-upload-server" }]);
    fireEvent.click(await screen.findByRole("button", { name: "Log" }));
    const consolePanel = await screen.findByRole("region", { name: "Capability apply console" });
    expect(consolePanel).toHaveTextContent("Saved capability changes were applied to running infrastructure");
    expect(consolePanel).toHaveTextContent("Optional-role Ansible apply succeeded");
    fireEvent.click(within(consolePanel).getByRole("button", { name: "Copy log" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(expect.stringContaining("job job-capability-apply")));
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("terraform"))).toBe(false);
  });

  it("restores saved-ready capability state after reload and applies that saved state", async () => {
    let currentWorkspace = optionalRoleCapabilityWorkspace(
      [{ hostClass: "homebase", id: "go-simple-upload-server" }],
      capabilityApplyState("saved_ready")
    );
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/apply")) {
        currentWorkspace = {
          ...currentWorkspace,
          applyState: capabilityApplyState("applying", [{ kind: "optional_roles", status: "running", jobId: "job-optional-apply", detail: "Applying Go Simple Upload Server." }])
        };
        return Promise.resolve(jsonResponse({
          capabilityApply: {
            status: "applying",
            applyState: currentWorkspace.applyState,
            job: { ...capabilityApplyJob("optional"), status: "running" }
          }
        }));
      }
      if (url.endsWith("/api/jobs/job-capability-apply")) {
        return Promise.resolve(jsonResponse({ job: { ...capabilityApplyJob("optional"), status: "running" } }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    const applyButton = await screen.findByRole("button", { name: "Apply saved changes" });
    expect(screen.getByText("Ready to apply")).toBeInTheDocument();
    expect(screen.getByText("Capability changes are saved and ready to apply.")).toBeInTheDocument();
    expect(applyButton).toBeEnabled();
    fireEvent.click(applyButton);

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/capabilities/apply",
      expect.objectContaining({ method: "POST", body: JSON.stringify({}) })
    ));
    expect(await screen.findByText("Saved capability changes are applying to running infrastructure.")).toBeInTheDocument();
    expect(screen.getByText(/Optional roles: Applying/)).toBeInTheDocument();
  });

  it("retries a terminal partial capability apply without requiring a selection change", async () => {
    let currentWorkspace = optionalRoleCapabilityWorkspace(
      [{ hostClass: "homebase", id: "go-simple-upload-server" }],
      capabilityApplyState("partial", [
        { kind: "optional_roles", status: "succeeded", jobId: "job-optional-apply", detail: "Optional roles applied." },
        { kind: "desktop", status: "failed", jobId: "job-desktop-apply", detail: "Desktop capability reconciliation failed; retry is required" }
      ])
    );
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) return Promise.resolve(jsonResponse({ capabilities: currentWorkspace }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/apply")) {
        currentWorkspace = {
          ...currentWorkspace,
          applyState: capabilityApplyState("applying", [
            { kind: "optional_roles", status: "running", jobId: "job-optional-retry", detail: "Retrying optional roles." },
            { kind: "desktop", status: "pending", jobId: "", detail: "Desktop retry will start after optional roles." }
          ])
        };
        return Promise.resolve(jsonResponse({
          capabilityApply: {
            status: "applying",
            applyState: currentWorkspace.applyState,
            job: { ...capabilityApplyJob("optional"), status: "running" }
          }
        }));
      }
      if (url.endsWith("/api/jobs/job-capability-apply")) return Promise.resolve(jsonResponse({ job: { ...capabilityApplyJob("optional"), status: "running" } }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    const retryButton = await screen.findByRole("button", { name: "Retry saved changes" });
    expect(retryButton).toBeEnabled();
    expect(screen.getByRole("button", { name: "Save capability changes" })).toBeDisabled();
    expect(screen.getByText(/core hosts remain running and may continue to incur provider charges/)).toBeInTheDocument();
    expect(screen.getByText(/retry saved changes, or use Infrastructure to tear down the engagement explicitly/)).toBeInTheDocument();
    fireEvent.click(retryButton);

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-zy01/capabilities/apply",
      expect.objectContaining({ method: "POST", body: JSON.stringify({}) })
    ));
    expect(await screen.findByText("Saved capability changes are applying to running infrastructure.")).toBeInTheDocument();
  });

  it("shows persisted configuration blockers without enabling apply", async () => {
    const blockedState = {
      ...capabilityApplyState("blocked", [{ kind: "optional_roles", status: "blocked", jobId: "", detail: "Configure the selected capability." }]),
      errors: ["Configure the selected capability."]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: optionalRoleCapabilityWorkspace([], blockedState) }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    expect(await screen.findByText("Configuration required")).toBeInTheDocument();
    expect(screen.getByText("Configuration required before applying saved capability changes. Configure the selected capability.")).toBeInTheDocument();
    expect(screen.getByText(/Optional roles: Blocked/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply saved changes" })).toBeDisabled();
  });

  it.each(["preserve", "restore-starter"])("previews and applies Static Web from the Capabilities workflow with %s", async (action) => {
    let currentOperations = operationsWithDeployedSketch([]);
    const renamedEngagement = { ...engagementSummary(), name: "RENAMED" };
    const configuredOperations = {
      ...operationsWithDeployedSketch([]),
      servicePlacements: [
        {
          hostId: "proxy01",
          hostRole: "proxy",
          service: "Static Web",
          status: "Configured",
          port: "8081",
          detail: "Static web site ff10 is configured behind the shared proxy front (site container :8081).",
          serviceId: "web-ff10",
          serviceType: "web-static",
          domain: "ff10.example.invalid",
          siteName: "ff10"
        }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [renamedEngagement] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: managedCapabilityWorkspace() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/static-web/sites/apply-preview")) {
        return Promise.resolve(jsonResponse(webStaticApplyPreviewJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/static-web/sites")) {
        currentOperations = configuredOperations;
        return Promise.resolve(jsonResponse(webStaticApplyJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: "Configure Static Web" }));
    const webWorkflow = screen.getByRole("region", { name: "Static web service workflow" });
    expect(within(webWorkflow).queryByLabelText("Web index html")).not.toBeInTheDocument();
    expect(within(webWorkflow).getByLabelText("Static web service placements")).toHaveTextContent("No Static Web sites are configured yet.");

    fireEvent.click(within(webWorkflow).getByRole("button", { name: "Add Site" }));
    const siteForm = within(webWorkflow).getByRole("region", { name: "Site Configuration" });
    expect(within(siteForm).queryByText("Content files")).not.toBeInTheDocument();
    expect(within(siteForm).queryByText("Starter index.html")).not.toBeInTheDocument();
    expect(within(siteForm).queryByRole("button", { name: "Select Files" })).not.toBeInTheDocument();
    expect(within(siteForm).queryByLabelText("Static web content files")).not.toBeInTheDocument();

    fireEvent.change(within(siteForm).getByLabelText("Web proxy"), { target: { value: "proxy01" } });
    fireEvent.change(within(siteForm).getByLabelText("Web site name"), { target: { value: "ff10" } });
    fireEvent.change(within(siteForm).getByLabelText("Web domain"), { target: { value: "ff10.example.invalid" } });
    expect(within(siteForm).getByText("proxy01 shared front :80/:443 → site container :8081")).toBeInTheDocument();
    expect(within(siteForm).getByText("Site Content Path")).toBeInTheDocument();
    expect(within(siteForm).getByText("/opt/web/ff10/html/")).toBeInTheDocument();
    fireEvent.change(within(siteForm).getByLabelText("Web site name"), { target: { value: "static-web.com" } });
    expect(within(siteForm).getByText("/opt/web/static-web_com/html/")).toBeInTheDocument();
    fireEvent.change(within(siteForm).getByLabelText("Web site name"), { target: { value: "www.example.ai" } });
    expect(within(siteForm).getByText("/opt/web/www_example_ai/html/")).toBeInTheDocument();
    fireEvent.change(within(siteForm).getByLabelText("Web site name"), { target: { value: "chat.redteam-example.com/path" } });
    expect(within(siteForm).getByText("/opt/web/chat_redteam-example_com_path/html/")).toBeInTheDocument();
    fireEvent.change(within(siteForm).getByLabelText("Web site name"), { target: { value: "ff10" } });
    expect(within(siteForm).getByRole("button", { name: "Apply Static Web" })).toBeDisabled();
    fireEvent.click(within(siteForm).getByRole("button", { name: "Preview Web Apply" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/static-web/sites/apply-preview",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            proxyId: "proxy01",
            siteName: "ff10",
            domain: "ff10.example.invalid",
            internalPort: "8081",
            contentAction: "preserve"
          })
        })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Static web apply preview result")).toHaveTextContent("/opt/web/ff10/html/index.html"));

    expect(within(siteForm).getByRole("radio", { name: "Preserve existing content" })).toBeChecked();
    if (action === "restore-starter") fireEvent.click(within(siteForm).getByRole("radio", { name: "Restore the “It works!” page" }));
    fireEvent.click(within(siteForm).getByRole("button", { name: "Apply Static Web" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/static-web/sites",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            proxyId: "proxy01",
            siteName: "ff10",
            domain: "ff10.example.invalid",
            internalPort: "8081",
            contentAction: action,
            contentReviewJobId: "job-web-static-preview"
          })
        })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Static web apply job result")).toHaveTextContent("job-web-static-apply"));
    await waitFor(() => expect(screen.getByLabelText("Static web service placements")).toHaveTextContent("ff10"));
    expect(screen.getByLabelText("Static web service placements")).not.toHaveTextContent("/opt/web/ff10/html/");
    expect(screen.getByLabelText("Static web service placements")).toHaveTextContent("Not Published");
    expect(screen.getByLabelText("Static web service placements")).toHaveTextContent("Not Managed");
    expect(screen.queryByText("Could not apply static web service.")).not.toBeInTheDocument();
    fireEvent.click(within(webWorkflow).getByRole("button", { name: "Publish Through Inbound Channel" }));
    const inboundModal = await screen.findByRole("region", { name: "Add inbound channel" });
    expect(within(inboundModal).getByLabelText("Inbound edge")).toHaveValue(JSON.stringify(["chain-1", "edge-chain-1"]));
    expect(within(inboundModal).getByLabelText("Inbound termination")).toHaveValue("proxy01-zy01");
    expect(within(inboundModal).getByLabelText("Inbound service")).toHaveTextContent("ff10 on proxy01 shared web front");
    expect(within(inboundModal).getByLabelText("Inbound mode")).toHaveValue("http-openresty");
    expect(within(inboundModal).getByLabelText("Inbound external port")).toHaveValue("80");
    expect(within(inboundModal).getByLabelText("Inbound internal port")).toHaveValue("80");
    expect(within(inboundModal).getByLabelText("Inbound internal port")).toBeDisabled();
  });

  it("shows the public HTTPS domain for a validated service-linked Static Web channel", async () => {
    const channel = {
      channelId: "edge-published-443-to-proxy01-443",
      domain: "published.example.invalid",
      protocol: "HTTPS",
      mode: "https-openresty",
      externalPort: "443",
      edge: "edge-zy01-us-sea-01",
      middle: "middle01-zy01",
      proxy: "proxy01-zy01",
      terminatesOn: "proxy01-zy01",
      service: "Static Web",
      serviceId: "web-published",
      serviceType: "web-static",
      internalPort: "443",
      purpose: "published site",
      status: "Validated",
      validation: { status: "Validated", externalIngressVerified: true }
    };
    const operations = {
      ...operationsWithDeployedSketch([channel]),
      servicePlacements: [{
        hostId: "proxy01",
        hostRole: "proxy",
        service: "Static Web",
        status: "Configured",
        port: "18080",
        detail: "Static web site published is configured.",
        serviceId: "web-published",
        serviceType: "web-static",
        domain: "published.example.invalid",
        siteName: "published"
      }]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) return Promise.resolve(jsonResponse({ capabilities: managedCapabilityWorkspace() }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: "Configure Static Web" }));
    const placements = await screen.findByLabelText("Static web service placements");
    expect(within(placements).getByRole("link", { name: "https://published.example.invalid/" })).toHaveAttribute(
      "href",
      "https://published.example.invalid/"
    );
    expect(placements).not.toHaveTextContent("Not Published");
  });

  it.each(["missing semantic ID", "mismatched expected hostname", "arbitrary FQDN", "duplicate semantic ID"])(
    "does not publish a service placement through %s core identity evidence",
    async (variant) => {
      const operations = {
        ...operationsWithDeployedSketch([]),
        servicePlacements: [{
          hostId: "proxy01", hostRole: "proxy", service: "Static Web", status: "Configured",
          port: "8081", detail: "configured", serviceId: "web-ff10", serviceType: "web-static",
          domain: "ff10.example.invalid", siteName: "ff10",
        }],
      };
      const proxy = operations.coreInfrastructure[1];
      if (variant === "missing semantic ID") {
        delete proxy.hostId;
      } else if (variant === "mismatched expected hostname") {
        proxy.expectedHostname = "proxy01-other";
      } else if (variant === "arbitrary FQDN") {
        proxy.hostname = proxy.expectedHostname = "proxy01-zy01.infra.redteam";
      } else {
        operations.coreInfrastructure.push({ ...proxy });
      }
      const fetchMock = vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
        if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [{ ...engagementSummary(), name: "RENAMED" }] }));
        if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
        if (url.endsWith("/api/engagements/eng-zy01/capabilities")) return Promise.resolve(jsonResponse({ capabilities: managedCapabilityWorkspace() }));
        if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
        return Promise.resolve(jsonResponse({}));
      });
      vi.stubGlobal("fetch", fetchMock);

      render(<App />);
      await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
      fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
      fireEvent.click(await screen.findByRole("button", { name: "Configure Static Web" }));
      const workflow = screen.getByRole("region", { name: "Static web service workflow" });
      fireEvent.click(within(workflow).getByRole("button", { name: "Configure" }));
      fireEvent.click(within(workflow).getByRole("button", { name: "Publish Through Inbound Channel" }));
      expect(screen.queryByRole("region", { name: "Add inbound channel" })).not.toBeInTheDocument();
    },
  );

  it("removes generated static web config while keeping the site record visible", async () => {
    const configuredOperations = {
      ...operationsOverview(""),
      servicePlacements: [
        {
          hostId: "proxy01",
          hostRole: "proxy",
          service: "Static Web",
          status: "Configured",
          port: "18080",
          detail: "Static web site ff10 is configured on 127.0.0.1:18080.",
          serviceId: "web-ff10",
          serviceType: "web-static",
          domain: "ff10.example.invalid",
          siteName: "ff10"
        }
      ]
    };
    const removedOperations = {
      ...configuredOperations,
      servicePlacements: configuredOperations.servicePlacements.map((placement) => ({ ...placement, status: "Removed" }))
    };
    let currentOperations = configuredOperations;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities")) {
        return Promise.resolve(jsonResponse({ capabilities: managedCapabilityWorkspace() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/static-web/sites/web-ff10/remove-preview")) {
        return Promise.resolve(jsonResponse(webStaticRemovePreviewJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/static-web/sites/web-ff10") && init?.method === "DELETE") {
        currentOperations = removedOperations;
        return Promise.resolve(jsonResponse(webStaticRemoveJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/static-web/sites/apply-preview")) return Promise.resolve(jsonResponse(webStaticApplyPreviewJob()));
      if (url.endsWith("/api/engagements/eng-zy01/capabilities/static-web/sites") && init?.method === "POST") {
        currentOperations = configuredOperations;
        return Promise.resolve(jsonResponse(webStaticApplyJob()));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: currentOperations }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: "Configure Static Web" }));
    const webWorkflow = screen.getByRole("region", { name: "Static web service workflow" });
    await waitFor(() => expect(within(webWorkflow).getByLabelText("Static web service placements")).toHaveTextContent("ff10"));
    const placements = within(webWorkflow).getByLabelText("Static web service placements");
    expect(within(placements).getByRole("button", { name: "Configure" })).toBeInTheDocument();
    expect(within(placements).queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(within(placements).queryByRole("button", { name: "Restore" })).not.toBeInTheDocument();
    expect(within(placements).queryByRole("button", { name: "Publish" })).not.toBeInTheDocument();

    fireEvent.click(within(placements).getByRole("button", { name: "Configure" }));
    const siteForm = within(webWorkflow).getByRole("region", { name: "Site Configuration" });
    expect(within(siteForm).getByRole("heading", { name: "Site Configuration" })).toBeInTheDocument();
    fireEvent.click(within(siteForm).getByRole("button", { name: "Remove" }));

    const confirmation = await within(siteForm).findByLabelText("Static Web removal confirmation for ff10");
    fireEvent.change(confirmation, { target: { value: "remove-web-ff10" } });
    fireEvent.click(within(siteForm).getByRole("button", { name: "Confirm Remove" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/static-web/sites/web-ff10",
        expect.objectContaining({
          method: "DELETE",
          body: JSON.stringify({ confirmation: "remove-web-ff10" })
        })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Static web service placements")).toHaveTextContent("Removed"));
    expect(screen.getByLabelText("Static web service placements")).not.toHaveTextContent("/opt/web/ff10/html/");
    expect(within(siteForm).getByText("/opt/web/ff10/html/")).toBeInTheDocument();
    expect(within(placements).getByRole("button", { name: "Configure" })).toBeInTheDocument();
    expect(within(placements).queryByRole("button", { name: "Restore" })).not.toBeInTheDocument();
    expect(within(siteForm).getByRole("button", { name: "Restore" })).toBeDisabled();
    fireEvent.click(within(siteForm).getByRole("button", { name: "Preview Web Apply" }));
    await within(siteForm).findByRole("radio", { name: "Preserve existing content" });
    fireEvent.click(within(siteForm).getByRole("button", { name: "Restore" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/capabilities/static-web/sites",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            proxyId: "proxy01",
            siteName: "ff10",
            domain: "ff10.example.invalid",
            internalPort: "8081",
            contentAction: "preserve",
            contentReviewJobId: "job-web-static-preview"
          })
        })
      )
    );
    await waitFor(() => expect(screen.getByLabelText("Static web service placements")).toHaveTextContent("Configured"));
  });

  it("manages engagement metadata from the global Engagements page", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01") && init?.method === "PATCH") {
        return Promise.resolve(jsonResponse({ engagement: { ...engagementSummary(), name: "ZY01 updated", description: "Updated metadata" } }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/lifecycle/reconcile") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          reconciliation: {
            previous: engagementSummary().lifecycle,
            current: { ...engagementSummary().lifecycle, state: "destroyed", label: "Destroyed", terminal: true },
            changed: true
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/archive") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ engagement: { ...engagementSummary(), status: "archived" } }));
      }
      if (url.endsWith("/api/engagements/eng-zy01") && init?.method === "DELETE") {
        return Promise.resolve(jsonResponse({ engagement: { ...engagementSummary(), status: "retired" } }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Engagements" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("ZY01"));

    fireEvent.click(screen.getByRole("button", { name: "Reconcile" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("Destroyed"));
    expect(screen.getByRole("button", { name: "Archive" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    expect(screen.queryByLabelText("Sketch state (DevTest pilot)")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Engagement metadata name")).toHaveValue("ZY01");
    fireEvent.change(screen.getByLabelText("Engagement metadata name"), {
      target: { value: "ZY01 updated" }
    });
    fireEvent.change(screen.getByLabelText("Engagement description"), {
      target: { value: "Updated metadata" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Engagement" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("ZY01 updated"));

    fireEvent.click(screen.getByRole("button", { name: "Archive" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Archived" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Archived" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("archived"));

    fireEvent.click(screen.getByRole("button", { name: "Retire" }));
    fireEvent.click(screen.getByRole("button", { name: "Retired" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("retired"));

    expect(fetchMock).toHaveBeenCalledWith("/api/engagements/eng-zy01", expect.objectContaining({ method: "PATCH" }));
    const patchRequest = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/api/engagements/eng-zy01") && init?.method === "PATCH");
    expect(JSON.parse(String(patchRequest?.[1]?.body))).not.toHaveProperty("sketchStateSchema");
    expect(fetchMock).toHaveBeenCalledWith("/api/engagements/eng-zy01/archive", expect.objectContaining({ method: "POST" }));
    expect(fetchMock).toHaveBeenCalledWith("/api/engagements/eng-zy01", expect.objectContaining({ method: "DELETE" }));
  });

  it.each([
    ["standard default", "split-v1", false],
    ["provider-keyed pilot", "provider-keyed-v2", true]
  ] as const)("creates an engagement with the %s sketch state", async (_label, expectedSchema, selectPilot) => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ engagement: engagementSummary({ name: "test", sketchStateSchema: expectedSchema }) }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Engagements" }));

    const schemaChoice = screen.getByLabelText("Sketch state (DevTest pilot)");
    expect(schemaChoice).toHaveValue("split-v1");
    if (selectPilot) fireEvent.change(schemaChoice, { target: { value: "provider-keyed-v2" } });
    fireEvent.change(screen.getByLabelText("Engagement metadata name"), { target: { value: "test" } });
    fireEvent.click(screen.getByRole("button", { name: "Create Engagement" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/engagements", expect.objectContaining({ method: "POST" })));
    const createRequest = fetchMock.mock.calls.find(([input, init]) => String(input).endsWith("/api/engagements") && init?.method === "POST");
    expect(JSON.parse(String(createRequest?.[1]?.body)).sketchStateSchema).toBe(expectedSchema);
    await waitFor(() => expect(schemaChoice).toHaveValue("split-v1"));
  });

  it("alerts instead of retiring an engagement with active infrastructure", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01") && init?.method === "DELETE") {
        return Promise.resolve(errorResponse(409, {
          error: "Engagement has active infrastructure. Tear down the infrastructure before archiving or retiring the engagement.",
          activeInfrastructure: { jobId: "job-active-infra" }
        }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Engagements" }));
    await waitFor(() => expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("ZY01"));
    fireEvent.click(screen.getByRole("button", { name: "Retire" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Tear down the infrastructure"));
    expect(screen.getByLabelText("Engagement metadata list")).toHaveTextContent("draft");
  });

  it("keeps inactive records with unsafe operational lifecycle visible in Current with recovery guidance", async () => {
    const archivedActive = engagementSummary({
      status: "archived",
      lifecycle: {
        ...engagementSummary().lifecycle,
        state: "active",
        label: "Active",
        terminal: false,
        administrativeStatus: "archived"
      }
    });
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [archivedActive] }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Engagements" }));
    const table = screen.getByLabelText("Engagement metadata list");
    await waitFor(() => expect(table).toHaveTextContent("ZY01"));
    expect(table).toHaveTextContent("Tear down infrastructure and verify cleanup");
    expect(within(table).getByRole("button", { name: "Archive" })).toBeDisabled();
    expect(within(table).getByRole("button", { name: "Retire" })).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Archived" }));
    expect(table).toHaveTextContent("ZY01");
  });

  it("manages provider credential aliases from Settings without rendering secrets", async () => {
    const credential = {
      id: "cred-linode",
      provider: "linode",
      alias: "linode-barragan",
      status: "active",
      description: "Linode sketch token",
      createdAt: "2026-06-03T00:00:00+00:00",
      updatedAt: "2026-06-03T00:00:00+00:00"
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/credentials") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ credential }));
      }
      if (url.endsWith("/api/credentials/cred-linode/validate") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ validation: { credential, decryptable: true } }));
      }
      if (url.endsWith("/api/credentials/cred-linode") && init?.method === "PATCH") {
        return Promise.resolve(jsonResponse({ credential: { ...credential, description: "Rotated token" } }));
      }
      if (url.endsWith("/api/credentials/cred-linode") && init?.method === "DELETE") {
        return Promise.resolve(jsonResponse({ credential: { ...credential, status: "disabled" } }));
      }
      if (url.endsWith("/api/provider-catalog/sketch/digitalocean/preflight") && init?.method === "POST") {
        return Promise.resolve(errorResponse(400, {
          preflight: {
            provider: "digitalocean",
            ready: false,
            catalogSource: "unavailable",
            checkedRegion: "sfo3",
            checkedSize: "s-1vcpu-1gb",
            errors: ["no active default digitalocean credential configured"],
            warnings: [],
            mutation: false,
            opsecBoundary: {
              directSketchAccessFromAppHost: false,
              middleAccess: "not used by provider preflight",
              edgeAccess: "not used by provider preflight"
            }
          }
        }));
      }
      if (url.endsWith("/api/provider-catalog/sketch/region-policies")) {
        return Promise.resolve(jsonResponse({
          policies: [
            { provider: "linode", allowedRegions: ["us-sea"], createdAt: "2026-06-08T00:00:00+00:00", updatedAt: "2026-06-08T00:00:00+00:00" },
            { provider: "digitalocean", allowedRegions: ["sfo3"], createdAt: "2026-06-08T00:00:00+00:00", updatedAt: "2026-06-08T00:00:00+00:00" }
          ]
        }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode&includeBlocked=1")) {
        return Promise.resolve(jsonResponse({
          catalog: {
            ...providerCatalog("linode"),
            regions: providerCatalog("linode").regions.map((region) => ({ ...region, allowed: region.id === "us-sea" })),
            regionPolicy: { allowedRegions: ["us-sea"], includeBlocked: true }
          }
        }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean&includeBlocked=1")) {
        return Promise.resolve(jsonResponse({
          catalog: {
            ...providerCatalog("digitalocean"),
            regions: providerCatalog("digitalocean").regions.map((region) => ({ ...region, allowed: true })),
            regionPolicy: { allowedRegions: ["sfo3"], includeBlocked: true }
          }
        }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs") && init?.method === "POST") {
        expect(init.body).toBe(JSON.stringify({ confirmCreateDestroy: "validate-digitalocean-sketch", requestedBy: "operator" }));
        return Promise.resolve(jsonResponse({
          job: {
            id: "job-do-smoke",
            action: "digitalocean_sketch_provider_validation",
            status: "running",
            targetType: "provider",
            targetId: "digitalocean",
            requestedBy: "operator",
            input: {
              provider: "digitalocean",
              alias: "do-barragan",
              confirmCreateDestroy: "redacted",
              mutation: true
            },
            artifactRefs: [],
            events: [
              {
                sequence: 1,
                level: "info",
                message: "DigitalOcean provider-smoke started",
                data: {
                  provider: "digitalocean",
                  mutation: true,
                  validationEvidence: {
                    status: "running",
                    cleanupVerified: false
                  }
                }
              }
            ]
          }
        }));
      }
      if (url.endsWith("/api/credentials")) {
        return Promise.resolve(jsonResponse({ credentials: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Global Settings" }));
    expect(screen.getByRole("button", { name: "User" })).toHaveClass("active");
    expect(screen.getByLabelText("User settings")).toBeInTheDocument();
    expect(screen.queryByLabelText("Provider credentials")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    await waitFor(() => expect(screen.getByLabelText("Provider credentials")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Credential alias"), {
      target: { value: "linode-barragan" }
    });
    fireEvent.change(screen.getByLabelText("Credential description"), {
      target: { value: "Linode sketch token" }
    });
    fireEvent.change(screen.getByLabelText("Credential secret"), {
      target: { value: "linode-token-sensitive-value" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Credential" }));

    await waitFor(() => expect(screen.getByLabelText("Credential aliases")).toHaveTextContent("linode-barragan"));
    expect(screen.queryByText("linode-token-sensitive-value")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Credential secret")).toHaveValue("");

    fireEvent.change(screen.getByLabelText("Credential description"), {
      target: { value: "Rotated token" }
    });
    fireEvent.change(screen.getByLabelText("Credential secret"), {
      target: { value: "new-linode-token-sensitive-value" }
    });
    fireEvent.click(screen.getByRole("button", { name: "Test" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("decrypts"));
    fireEvent.click(screen.getByRole("button", { name: "Rotate" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Rotated linode/linode-barragan"));
    expect(screen.queryByText("new-linode-token-sensitive-value")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Disable" }));
    await waitFor(() => expect(screen.getByLabelText("Credential aliases")).toHaveTextContent("disabled"));
    fireEvent.click(screen.getByRole("button", { name: "Check DigitalOcean Sketch Readiness" }));
    await waitFor(() => expect(screen.getByLabelText("DigitalOcean preflight result")).toHaveTextContent("sfo3"));
    expect(screen.getByLabelText("DigitalOcean preflight result")).toHaveTextContent("s-1vcpu-1gb");
    expect(screen.getByLabelText("DigitalOcean preflight result")).toHaveTextContent("No");
    expect(screen.getByLabelText("DigitalOcean preflight result")).toHaveTextContent("None from app host");
    expect(screen.queryByText("do-token-sensitive-value")).not.toBeInTheDocument();
    expect(screen.queryByText("do-live-preflight")).not.toBeInTheDocument();
    expect(screen.queryByText("TF_VAR_do_pat")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Provider-Smoke Validation" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("DigitalOcean provider-smoke confirmation"), {
      target: { value: "validate-digitalocean-sketch" }
    });
    expect(screen.getByRole("button", { name: "Run Provider-Smoke Validation" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Run Provider-Smoke Validation" }));
    await waitFor(() => expect(screen.getByLabelText("DigitalOcean provider-smoke job result")).toHaveTextContent("job-do-smoke"));
    expect(screen.getByLabelText("DigitalOcean provider-smoke job result")).toHaveTextContent("running");
    expect(screen.queryByText("do-token-sensitive-value")).not.toBeInTheDocument();
    expect(screen.queryByText("TF_VAR_do_pat")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Barragan App" }));
    expect(screen.getByLabelText("Barragan application settings")).toHaveTextContent("Application settings");
    expect(screen.queryByLabelText("Provider credentials")).not.toBeInTheDocument();

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/credentials",
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining("linode-token-sensitive-value")
      })
    );
    expect(fetchMock).toHaveBeenCalledWith("/api/credentials/cred-linode", expect.objectContaining({ method: "PATCH" }));
    expect(fetchMock).toHaveBeenCalledWith("/api/credentials/cred-linode", expect.objectContaining({ method: "DELETE" }));
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/provider-catalog/sketch/digitalocean/preflight",
      expect.objectContaining({ method: "POST" })
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("keeps registrar credential providers out of sketch provider selectors", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/credentials")) {
        return Promise.resolve(jsonResponse({ credentials: [] }));
      }
      if (url.endsWith("/api/provider-catalog/sketch/region-policies")) {
        return Promise.resolve(jsonResponse({
          policies: [
            { provider: "linode", allowedRegions: ["us-sea"], createdAt: "2026-06-08T00:00:00+00:00", updatedAt: "2026-06-08T00:00:00+00:00" },
            { provider: "digitalocean", allowedRegions: ["sfo3"], createdAt: "2026-06-08T00:00:00+00:00", updatedAt: "2026-06-08T00:00:00+00:00" }
          ]
        }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode&includeBlocked=1")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean&includeBlocked=1")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Global Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    await waitFor(() => expect(screen.getByLabelText("Provider credentials")).toBeInTheDocument());

    const credentialProvider = screen.getByLabelText("Credential provider") as HTMLSelectElement;
    expect(Array.from(credentialProvider.options).map((option) => option.value)).toEqual(["linode", "digitalocean", "namecheap"]);

    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));

    const middleProvider = await screen.findByLabelText("proxy01-chain-1 middle provider") as HTMLSelectElement;
    const edgeProvider = screen.getByLabelText("proxy01-chain-1 edge provider") as HTMLSelectElement;
    expect(Array.from(middleProvider.options).map((option) => option.value)).toEqual(["linode", "digitalocean"]);
    expect(Array.from(edgeProvider.options).map((option) => option.value)).toEqual(["linode", "digitalocean"]);
  });

  it("manages sketch provider region allowlists from Settings and filters Infrastructure regions", async () => {
    let linodeAllowedRegions = ["us-sea"];
    const fullLinodeCatalog = providerCatalog("linode");
    const filteredLinodeCatalog = () => ({
      ...fullLinodeCatalog,
      regions: fullLinodeCatalog.regions.filter((region) => linodeAllowedRegions.includes(region.id)),
      regionPolicy: {
        allowedRegions: linodeAllowedRegions,
        includeBlocked: false
      }
    });
    const settingsLinodeCatalog = () => ({
      ...fullLinodeCatalog,
      regions: fullLinodeCatalog.regions.map((region) => ({
        ...region,
        allowed: linodeAllowedRegions.includes(region.id)
      })),
      regionPolicy: {
        allowedRegions: linodeAllowedRegions,
        includeBlocked: true
      }
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/credentials")) {
        return Promise.resolve(jsonResponse({ credentials: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: filteredLinodeCatalog() }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch/region-policies")) {
        return Promise.resolve(jsonResponse({
          policies: [
            { provider: "linode", allowedRegions: linodeAllowedRegions, createdAt: "2026-06-08T00:00:00+00:00", updatedAt: "2026-06-08T00:00:00+00:00" },
            { provider: "digitalocean", allowedRegions: ["sfo3"], createdAt: "2026-06-08T00:00:00+00:00", updatedAt: "2026-06-08T00:00:00+00:00" }
          ]
        }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode&includeBlocked=1")) {
        return Promise.resolve(jsonResponse({ catalog: settingsLinodeCatalog() }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean&includeBlocked=1")) {
        return Promise.resolve(jsonResponse({ catalog: { ...providerCatalog("digitalocean"), regionPolicy: { allowedRegions: ["sfo3"], includeBlocked: true } } }));
      }
      if (url.endsWith("/api/provider-catalog/sketch/region-policies/linode") && init?.method === "PATCH") {
        linodeAllowedRegions = JSON.parse(String(init.body)).allowedRegions;
        return Promise.resolve(jsonResponse({
          policy: {
            provider: "linode",
            allowedRegions: linodeAllowedRegions,
            createdAt: "2026-06-08T00:00:00+00:00",
            updatedAt: "2026-06-08T00:05:00+00:00"
          }
        }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    const initialMiddleRegion = await screen.findByLabelText("proxy01-chain-1 middle region") as HTMLSelectElement;
    expect(Array.from(initialMiddleRegion.options).map((option) => option.value)).toEqual(["us-sea"]);

    fireEvent.click(within(screen.getByRole("navigation", { name: "Global" })).getByRole("button", { name: "Global Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Cloud Providers" }));
    await waitFor(() => expect(screen.getByLabelText("Sketch region allowlist")).toBeInTheDocument());
    const usOrdCheckbox = screen.getByLabelText("linode us-ord") as HTMLInputElement;
    expect(usOrdCheckbox.checked).toBe(false);
    fireEvent.click(usOrdCheckbox);

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/provider-catalog/sketch/region-policies/linode",
        expect.objectContaining({
          method: "PATCH",
          body: JSON.stringify({ allowedRegions: ["us-ord", "us-sea"] })
        })
      )
    );
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => {
      const updatedMiddleRegion = screen.getByLabelText("proxy01-chain-1 middle region") as HTMLSelectElement;
      expect(Array.from(updatedMiddleRegion.options).map((option) => option.value)).toEqual(["us-sea", "us-ord"]);
    });
  });

  it("blocks deployment of pending durable sketch chains outside the active region allowlist", async () => {
    const staleChain = sketchChainRecordFromBody("proxy01-lax-01", {
      assignedProxy: "proxy01",
      middleProvider: "linode",
      middleRegion: "us-sea",
      middleSize: "g6-nanode-1",
      edgeProvider: "linode",
      edgeRegion: "us-lax",
      edgeSize: "g6-nanode-1"
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) {
        return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({
          catalog: {
            ...providerCatalog("linode"),
            regions: providerCatalog("linode").regions.filter((region) => region.id === "us-sea"),
            regionPolicy: { allowedRegions: ["us-sea"], includeBlocked: false }
          }
        }));
      }
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) {
        return Promise.resolve(jsonResponse({ sketchChains: [staleChain] }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText("proxy01-lax-01")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("outside the current sketch region allowlist");
    expect(screen.getByRole("status")).toHaveTextContent("edge linode/us-lax");
    expect(screen.getByLabelText("proxy01-lax-01 live default edge region")).toHaveDisplayValue("us-lax (not allowed)");
    expect(screen.getByRole("button", { name: "Deploy New Chain" })).toBeDisabled();
    expect(
      fetchMock.mock.calls.some(([input, init]) =>
        String(input).endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-lax-01/deploy") && init?.method === "POST"
      )
    ).toBe(false);
  });

  it("renders independently selectable provider, region, and size controls for each pending edge", async () => {
    let chain = {
      ...sketchChainRecord("proxy01-mixed-01"),
      edgeCount: 2,
      edges: [
        { id: "edge-01", provider: "linode", region: "us-sea", size: "g6-nanode-1" },
        { id: "edge-02", provider: "digitalocean", region: "sfo3", size: "s-1vcpu-1gb" }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) return Promise.resolve(jsonResponse({ sketchChains: [chain] }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-mixed-01") && init?.method === "PATCH") {
        const patch = JSON.parse(String(init.body));
        chain = { ...chain, ...patch, edges: patch.edges ?? chain.edges };
        return Promise.resolve(jsonResponse({ sketchChain: chain }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText("proxy01-mixed-01")).toBeInTheDocument());

    expect(screen.getByLabelText("proxy01-mixed-01 live edge 01 provider")).toHaveDisplayValue("linode");
    expect(screen.getByLabelText("proxy01-mixed-01 live edge 02 provider")).toHaveDisplayValue("digitalocean");
    expect((screen.getByLabelText("proxy01-mixed-01 live edge 02 region") as HTMLSelectElement).value).toBe("sfo3");
    expect((screen.getByLabelText("proxy01-mixed-01 live edge 02 size") as HTMLSelectElement).value).toBe("s-1vcpu-1gb");

    fireEvent.change(screen.getByLabelText("proxy01-mixed-01 live edge 02 provider"), { target: { value: "linode" } });
    await waitFor(() => expect(screen.getByLabelText("proxy01-mixed-01 live edge 02 provider")).toHaveDisplayValue("linode"));
    const updateCall = fetchMock.mock.calls.find(([input, init]) =>
      String(input).endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-mixed-01") && init?.method === "PATCH"
    );
    expect(JSON.parse(String(updateCall?.[1]?.body))).toMatchObject({
      edgeProvider: "linode",
      edgeRegion: "us-sea",
      edgeSize: "g6-nanode-1",
      edges: [
        { id: "edge-01", provider: "linode", region: "us-sea", size: "g6-nanode-1" },
        { id: "edge-02", provider: "linode", region: "us-sea", size: "g6-nanode-1" }
      ]
    });
  });


  it("refreshes selected engagement input when preparing infrastructure for an existing plan", async () => {
    const selectedEngagement = {
      ...engagementSummary(),
      id: "eng-vg01",
      name: "VG01",
      status: "planned",
      templateId: "standard-rti",
      activeRevision: "rev-stale",
      inputParameters: standardInput()
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "0.1.0", description: "Baseline", defaultNodeGroups: ["homebase"], supportedProviders: ["oci"] }] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [selectedEngagement] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({
          dashboard: {
            generatedAt: "2026-06-09T00:00:00+00:00",
            summary: {
              templates: 1,
              engagements: 1,
              activeEngagements: 0,
              jobRuns: 0,
              activeInfrastructure: 0,
              attention: 0,
              destroyed: 0,
              lastKnown: 0,
              orphanCandidates: 0
            },
            inventory: [],
            orphanCandidates: [],
            reconciliation: {
              status: "local-records",
              detail: "Dashboard inventory is derived from Barragan runtime records."
            }
          }
        }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.includes("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.includes("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-vg01/operations")) {
        return Promise.resolve(jsonResponse({ operations: { ...emptyOperationsOverview(""), engagementId: "eng-vg01" } }));
      }
      if (url.endsWith("/api/engagements/eng-vg01/sketch-chains") && !init?.method) {
        return Promise.resolve(jsonResponse({ sketchChains: [] }));
      }
      if (url.endsWith("/api/engagements/eng-vg01/infrastructure") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          engagement: {
            ...selectedEngagement,
            templateId: "standard-rti",
            inputParameters: JSON.parse(String(init.body)).inputParameters
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-vg01/revisions") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ revision: { id: "rev-eng-vg01-r0001", engagementId: "eng-vg01", revisionNumber: 1, status: "compiled", templateId: "standard-rti", inputParameters: {}, resolvedTopology: {}, runIntent: [], validationGates: validationGates() } }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "1. Select Template And Customizations" })).toBeInTheDocument());
    const elkToggle = screen.getByRole("checkbox", { name: "Include ELK node" });
    expect(elkToggle).not.toBeChecked();
    fireEvent.click(elkToggle);
    expect(elkToggle).toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));

    await waitFor(() =>
      expect(fetchMock.mock.calls.some(([input, init]) =>
        String(input).endsWith("/api/engagements/eng-vg01/infrastructure") && init?.method === "POST"
      )).toBe(true)
    );
    const infrastructureCall = fetchMock.mock.calls.find(([input, init]) =>
      String(input).endsWith("/api/engagements/eng-vg01/infrastructure") && init?.method === "POST"
    );
    const infrastructureBody = JSON.parse(String(infrastructureCall?.[1]?.body));
    expect(infrastructureBody.inputParameters.engagementName).toBe("VG01");
    expect(infrastructureBody.inputParameters.elkEnabled).toBe(true);
  });


  it("prepares, invalidates, and applies the exact engagement core plan", async () => {
    let prepareSequence = 0;
    const selectedEngagement = {
      ...engagementSummary(),
      id: "eng-plan-ui",
      name: "ZY01",
      templateId: "standard-rti",
      inputParameters: standardInput()
    };
    const plan = (id: string) => ({
      id,
      engagementId: selectedEngagement.id,
      revisionId: "rev-plan-ui",
      status: "ready",
      stage: "Terraform plan saved",
      counts: { add: 4, update: 1, replace: 0, remove: 0, read: 2 },
      resourceChanges: [
        { action: "add", address: "oci_core_instance.homebase", type: "OCI instance", provider: "oci", displayName: "Homebase", group: "Compute", region: "us-ashburn-1" },
        { action: "update", address: "oci_core_vcn.engagement", type: "OCI VCN", provider: "oci", displayName: "Engagement network", group: "Network", region: "us-ashburn-1" }
      ],
      target: { name: "barragan-testing", region: "us-ashburn-1" },
      reviewedConfiguration: {
        templateId: "standard-rti",
        templateName: "Standard RTI",
        core: { homebases: 1, proxies: 2, elkEnabled: false },
        target: { name: "barragan-testing", region: "us-sanjose-1" },
        sshSourceCidrs: prepareSequence > 1 ? ["160.34.88.0/23"] : ["160.34.86.0/23"]
      },
      postCoreScope: {
        chainCount: 2,
        middleCount: 2,
        edgeCount: 4,
        providers: ["digitalocean", "linode"],
        chains: ["proxy01", "proxy02"].map((proxy) => ({
          id: `${proxy}-chain-1`,
          assignedProxy: proxy,
          middle: { provider: "linode", region: "us-sea" },
          edges: [1, 2].map((index) => ({ id: `edge-${String(index).padStart(2, "0")}`, provider: "digitalocean", region: "sfo3" }))
        }))
      },
      preparedAt: "2026-08-05T14:00:00Z",
      ageWarningAt: "2099-08-05T15:00:00Z",
      sshSourceCidrs: prepareSequence > 1 ? ["160.34.88.0/23"] : ["160.34.86.0/23"],
      inputFingerprint: `fingerprint-${id}`,
      computeProfile: standardComputeProfileFixture(),
      sanitizedTextKind: "summary",
      sanitizedText: "Plan: 4 to add, 1 to change, 0 to destroy.",
      terraformFiles: [{ path: "core/main.tf", language: "hcl", content: 'resource "oci_core_instance" "homebase" {}\n' }],
      error: null
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "0.1.0", description: "Baseline", defaultNodeGroups: ["homebase"], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [selectedEngagement] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.includes("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/engagements/eng-plan-ui/operations")) {
        return Promise.resolve(jsonResponse({ operations: { ...emptyOperationsOverview(""), engagementId: "eng-plan-ui" } }));
      }
      if (url.endsWith("/api/engagements/eng-plan-ui/sketch-chains") && !init?.method) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-plan-ui/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-plan-ui") }));
      if (url.endsWith("/api/engagements/eng-plan-ui/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan: null }));
      if (url.endsWith("/api/engagements/eng-plan-ui/infrastructure") && init?.method === "POST") return Promise.resolve(jsonResponse({ engagement: selectedEngagement }));
      if (url.endsWith("/api/engagements/eng-plan-ui/revisions") && init?.method === "POST") return Promise.resolve(jsonResponse({ revision: { id: "rev-plan-ui", engagementId: "eng-plan-ui", revisionNumber: 1, status: "compiled", templateId: "standard-rti", inputParameters: {}, resolvedTopology: {}, runIntent: [], validationGates: validationGates() } }));
      if (url.endsWith("/api/engagements/eng-plan-ui/deployment-plans") && init?.method === "POST") {
        prepareSequence += 1;
        return Promise.resolve(jsonResponse({ plan: plan(`plan-ui-${prepareSequence}`) }));
      }
      if (url.endsWith("/api/engagements/eng-plan-ui/deployment-plans/plan-ui-2/apply") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ plan: { ...plan("plan-ui-2"), status: "applying" }, job: pilotRunningJob("eng-plan-ui") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "2. Review Infrastructure Plan" })).toBeInTheDocument());
    expect(screen.getByRole("heading", { name: "3. Deploy Infrastructure" })).toBeInTheDocument();
    expect(screen.getByText("Deployment is locked.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show Review" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Preview Changes" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Sketch deployment activity")).not.toBeInTheDocument();
    expect(screen.queryByText("Durable IaC Workspace")).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("SSH allowed CIDRs"), { target: { value: "" } });
    expect(screen.getByRole("button", { name: "Prepare Infrastructure Plan" })).toBeDisabled();

    fireEvent.change(screen.getByLabelText("SSH allowed CIDRs"), { target: { value: "160.34.86.0/23" } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));
    await waitFor(() => expect(screen.getByLabelText("Saved core Terraform plan")).toHaveTextContent("plan-ui-1"));
    expect(screen.getByLabelText("Terraform action counts")).toHaveTextContent("Add4Update1Replace0Remove0");
    expect(screen.getByLabelText("Compute resource changes")).toHaveTextContent("AddHomebase");
    const computeProfile = screen.getByLabelText("Resolved compute profile");
    expect(computeProfile).toHaveTextContent("Standard RTI");
    expect(computeProfile).toHaveTextContent("standard-rti");
    expect(computeProfile).toHaveTextContent("a".repeat(64));
    expect(within(computeProfile).getByLabelText("Homebase compute sizing")).toHaveTextContent("1 nodeShapeBM.Standard3.64OCPUs64RAM1,024 GBBoot volume512 GiB");
    expect(within(computeProfile).getByLabelText("Proxy compute sizing")).toHaveTextContent("2 nodesShapeVM.Standard.E4.FlexOCPUs2RAM32 GBBoot volume512 GiB");
    expect(within(computeProfile).getByLabelText("ELK compute sizing")).toHaveTextContent("0 nodesShapeVM.Standard.E4.FlexOCPUs2RAM32 GBBoot volume512 GiB");
    expect(within(computeProfile).queryByRole("textbox")).not.toBeInTheDocument();
    expect(within(computeProfile).queryByRole("spinbutton")).not.toBeInTheDocument();
    expect(within(computeProfile).queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Validated post-core rollout")).toHaveTextContent("not part of that Terraform artifact");
    fireEvent.click(screen.getByText("Advanced Terraform evidence"));
    expect(screen.getByLabelText("Sanitized plan summary")).toHaveTextContent("4 to add");
    expect(screen.getByLabelText("Terraform source core/main.tf")).toHaveTextContent("oci_core_instance");
    expect(screen.queryByText("linode-barragan")).not.toBeInTheDocument();
    expect(screen.queryByText(/terraform\.tfstate|credentialAlias|secret:\/\//)).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "3. Deploy Infrastructure" })).toHaveFocus();
    expect(screen.getByRole("button", { name: "Deploy" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Confirmation token"), { target: { value: "wrong-token" } });
    expect(screen.getByRole("button", { name: "Deploy" })).toBeDisabled();

    const persistedPostCore = screen.getByLabelText("Validated post-core rollout");
    fireEvent.change(screen.getByLabelText("proxy01-chain-1 edge provider"), { target: { value: "linode" } });
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Plan is outdated"));
    expect(persistedPostCore).toHaveTextContent("digitalocean/sfo3 edge");
    expect(persistedPostCore).not.toHaveTextContent("linode/us-sea edge");
    fireEvent.change(screen.getByLabelText("proxy01-chain-1 edge provider"), { target: { value: "digitalocean" } });
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("SSH allowed CIDRs"), { target: { value: "160.34.88.0/23" } });
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Plan is outdated"));
    expect(screen.queryByLabelText("Guided deployment confirmation")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));
    await waitFor(() => expect(screen.getByLabelText("Saved core Terraform plan")).toHaveTextContent("plan-ui-2"));
    fireEvent.change(screen.getByLabelText("Confirmation token"), { target: { value: "mutate-barragan-testing" } });
    fireEvent.click(screen.getByRole("button", { name: "Deploy" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/deployment-plans/plan-ui-2/apply"))).toBe(true));
    const applyCall = fetchMock.mock.calls.find(([input]) => String(input).endsWith("/deployment-plans/plan-ui-2/apply"));
    expect(JSON.parse(String(applyCall?.[1]?.body))).toEqual({ confirmMutation: "mutate-barragan-testing" });
    const secondPrepareCall = fetchMock.mock.calls.filter(([input, init]) => String(input).endsWith("/deployment-plans") && init?.method === "POST")[1];
    expect(JSON.parse(String(secondPrepareCall?.[1]?.body))).toEqual({ revisionId: "rev-plan-ui", sshSourceCidrs: ["160.34.88.0/23"] });
  });

  it("restores a saved plan without treating different editor CIDRs as current", async () => {
    const savedPlan = corePlanReviewFixture({ sshSourceCidrs: ["10.20.30.0/24"] });
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Baseline", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ templateId: "standard-rti" })] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.includes("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan: savedPlan }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));

    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Plan is outdated"));
    expect(screen.getByLabelText("Infrastructure plan review")).toHaveTextContent("10.20.30.0/24");
    expect(screen.getByLabelText("SSH allowed CIDRs")).not.toHaveValue(expect.stringContaining("10.20.30.0/24"));
    expect(screen.queryByLabelText("Guided deployment confirmation")).not.toBeInTheDocument();
    expect(screen.getByText("Deployment is locked.")).toBeInTheDocument();
  });

  it("hydrates Small Dev Sketch inputs from engagement detail and keeps a matching saved plan ready", async () => {
    const cidrs = pilotReadiness().sshIngress.defaultSourceCidrs;
    const sketchChains = ["sfo3", "nyc3"].map((region) => ({
      id: `proxy01-chain-${region === "sfo3" ? 1 : 2}`,
      assignedProxy: "proxy01",
      middleProvider: "digitalocean",
      middleRegion: region,
      middleSize: "s-1vcpu-1gb",
      edgeProvider: "digitalocean",
      edgeRegion: region,
      edgeSize: "s-1vcpu-1gb",
      edgeCount: 1,
      edges: [{ id: "edge-01", provider: "digitalocean", region, size: "s-1vcpu-1gb" }]
    }));
    const engagement = engagementSummary({
      templateId: "small-dev-infra",
      activeRevision: "rev-plan-current",
      sketchStateSchema: "provider-keyed-v2"
    });
    const detail = {
      ...engagement,
      inputParameters: {
        engagementName: "ZY01",
        proxyCount: 1,
        elkEnabled: false,
        deploymentTarget: { provider: "oci", name: "barragan-testing", region: "us-sanjose-1", compartmentId: pilotReadiness().target.compartmentId },
        sketchChains
      }
    };
    const plan = corePlanReviewFixture({
      sketchStateSchema: "provider-keyed-v2",
      sshSourceCidrs: cidrs,
      reviewedConfiguration: {
        templateId: "small-dev-infra",
        templateName: "Small Dev Infra",
        core: { homebases: 1, proxies: 1, elkEnabled: false },
        target: { name: "barragan-testing", region: "us-sanjose-1" },
        sshSourceCidrs: cidrs
      },
      postCoreScope: {
        chainCount: 2,
        middleCount: 2,
        edgeCount: 2,
        providers: ["digitalocean"],
        chains: sketchChains.map((chain) => ({
          id: chain.id,
          assignedProxy: chain.assignedProxy,
          middle: { provider: chain.middleProvider, region: chain.middleRegion },
          edges: chain.edges.map((edge) => ({ id: edge.id, provider: edge.provider, region: edge.region }))
        }))
      }
    });
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "small-dev-infra", name: "Small Dev Infra", version: "1", description: "Small", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagement] }));
      if (url.endsWith("/api/engagements/eng-zy01")) return Promise.resolve(jsonResponse({ engagement: detail }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) {
        const provider = url.includes("provider=linode") ? "linode" : "digitalocean";
        const catalog = providerCatalog(provider);
        return Promise.resolve(jsonResponse({ catalog: provider === "digitalocean" ? {
          ...catalog,
          regions: [...catalog.regions, { id: "nyc3", label: "New York 3", available: true }],
          sizes: catalog.sizes.map((size) => ({ ...size, regions: ["sfo3", "nyc3"] })),
          regionPolicy: { allowedRegions: ["sfo3", "nyc3"], includeBlocked: false }
        } : catalog }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByLabelText("proxy01-chain-2 middle region")).toHaveValue("nyc3"));
    expect(screen.getByLabelText("Infrastructure template")).toHaveValue("small-dev-infra");
    expect(screen.getByLabelText("Proxy count")).toHaveValue("1");
    expect(screen.getByLabelText("Include ELK node")).not.toBeChecked();
    expect(screen.getByLabelText("proxy01-chain-1 middle provider")).toHaveValue("digitalocean");
    expect(screen.getByLabelText("proxy01-chain-2 default edge region")).toHaveValue("nyc3");
    await waitFor(() => expect(screen.queryByText("Plan is outdated.")).not.toBeInTheDocument());
    expect(screen.getByLabelText("Saved core Terraform plan")).toHaveTextContent("plan-current");

    fireEvent.change(screen.getByLabelText("proxy01-chain-2 default edge region"), { target: { value: "sfo3" } });
    await waitFor(() => expect(screen.getByText("Plan is outdated.")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByLabelText("proxy01-chain-2 default edge region")).toHaveValue("sfo3"));
    expect(screen.getByText("Plan is outdated.")).toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/api/engagements/eng-zy01"))).toHaveLength(1);
  });

  it("does not overwrite operator Sketch and target edits when engagement detail arrives late", async () => {
    let resolveDetail!: (response: Response) => void;
    const deferredDetail = new Promise<Response>((resolve) => { resolveDetail = resolve; });
    const engagement = engagementSummary({ templateId: "standard-rti" });
    let detailReads = 0;
    const persistedDetail = {
      ...engagement,
      inputParameters: {
        elkEnabled: true,
        deploymentTarget: { name: "barragan-testing" },
        sketchChains: [{
          assignedProxy: "proxy01", middleProvider: "digitalocean", middleRegion: "sfo3", middleSize: "s-1vcpu-1gb",
          edgeProvider: "digitalocean", edgeRegion: "sfo3", edgeSize: "s-1vcpu-1gb",
          edges: [{ id: "edge-01", provider: "digitalocean", region: "sfo3", size: "s-1vcpu-1gb" }]
        }]
      }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Standard", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagement] }));
      if (url.endsWith("/api/engagements/eng-zy01")) return ++detailReads === 1 ? deferredDetail : Promise.resolve(jsonResponse({ engagement: persistedDetail }));
      if (url.endsWith("/api/engagements/eng-zy01/infrastructure") && init?.method === "POST") return Promise.resolve(jsonResponse({ engagement: persistedDetail }));
      if (url.endsWith("/api/engagements/eng-zy01/revisions") && init?.method === "POST") return Promise.resolve(jsonResponse({ revision: {
        id: "rev-edited", engagementId: "eng-zy01", revisionNumber: 1, status: "compiled", templateId: "standard-rti",
        inputParameters: persistedDetail.inputParameters, resolvedTopology: {}, runIntent: [], validationGates: validationGates()
      } }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans") && init?.method === "POST") return Promise.resolve(jsonResponse({ plan: corePlanReviewFixture() }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("provider=linode") ? "linode" : "digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan: null }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    const middleRegion = await screen.findByLabelText("proxy01-chain-1 middle region");
    await waitFor(() => expect(middleRegion).not.toBeDisabled());
    fireEvent.change(middleRegion, { target: { value: "us-ord" } });
    fireEvent.change(screen.getByLabelText("Target compartment"), { target: { value: "RedTeam-1" } });
    resolveDetail(jsonResponse({ engagement: persistedDetail }));
    await waitFor(() => expect(screen.getByLabelText("Include ELK node")).toBeChecked());
    expect(screen.getByLabelText("proxy01-chain-1 middle region")).toHaveValue("us-ord");
    expect(screen.getByLabelText("proxy01-chain-1 middle provider")).toHaveValue("linode");
    expect(screen.getByLabelText("Target compartment")).toHaveValue("RedTeam-1");
    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));
    await waitFor(() => expect(detailReads).toBe(2));
    expect(screen.getByLabelText("proxy01-chain-1 middle region")).toHaveValue("us-ord");
    expect(screen.getByLabelText("Target compartment")).toHaveValue("RedTeam-1");
  });

  it("shows the exact running core job during deployment before any core host is inventoried", async () => {
    let resolveJob!: (response: Response) => void;
    const deferredJob = new Promise<Response>((resolve) => { resolveJob = resolve; });
    const job = pilotRunningJob("eng-zy01");
    const operations = {
      ...emptyOperationsOverview(""),
      lifecycle: { state: "deploying", label: "Deploying", attentionRequired: false, terminal: false,
        evidence: [{ kind: "core_job", id: job.id, status: "running" }] },
      coreJob: { id: "job-prior-success", action: job.action, status: "succeeded" },
      activeJob: { id: "job-child-inspector", action: "inspector_prepare", status: "running" }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Standard", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ templateId: "standard-rti" })] }));
      if (url.endsWith("/api/engagements/eng-zy01")) return Promise.resolve(jsonResponse({ engagement: { ...engagementSummary({ templateId: "standard-rti" }), inputParameters: {} } }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("provider=linode") ? "linode" : "digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan: null }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${job.id}`)) return deferredJob;
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText("Barragan is loading the current core deployment job before showing progress.")).toBeInTheDocument());
    expect(screen.queryByText("Cleanup recovery unavailable")).not.toBeInTheDocument();
    resolveJob(jsonResponse({ job }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Deploying Infrastructure" })).toBeInTheDocument());
    expect(screen.getByLabelText("Current core infrastructure")).toHaveTextContent(job.id);
    expect(screen.getByRole("button", { name: "Open Console" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Tear Down Infrastructure" })).not.toBeInTheDocument();
  });

  it.each([
    [true, false, false],
    [false, false, false],
    [true, true, false],
    [true, false, true]
  ] as const)("uses the normal Deploy action when keyed eligibility is %s, plan mode mismatch is %s, and mixed scope is %s", async (eligible, mismatch, mixed) => {
    const engagement = engagementSummary({ sketchStateSchema: "provider-keyed-v2", templateId: "standard-rti" });
    const basePlan = corePlanReviewFixture();
    const plan = corePlanReviewFixture({
      keyedDeployEligible: eligible,
      reviewedConfiguration: mixed ? {
        ...basePlan.reviewedConfiguration,
        sketchAuthorization: {
          kind: "bounded-mixed-post-core-v1",
          providerScopes: ["linode", "digitalocean"].map((provider, index) => ({
            provider, providerConnectionId: `connection-${provider}`,
            image: `${provider}/ubuntu24.04`,
            chain: { id: `proxy0${index + 1}-chain-1`, assignedProxy: `proxy0${index + 1}`,
              middle: { provider, region: "region-a", size: "small" },
              edges: [{ id: `edge-${provider}`, provider, region: "region-a", size: "small" }] },
            firewall: { publicTcpPorts: ["80", "443", "2222"], publicUdpPorts: [], publicIpv6Allowed: false }
          }))
        }
      } : basePlan.reviewedConfiguration,
      postCoreScope: {
        ...basePlan.postCoreScope,
        sketchStateSchema: mismatch ? "split-v1" : "provider-keyed-v2"
      }
    });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Baseline", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagement] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("provider=linode") ? "linode" : "digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan: null }));
      if (url.endsWith("/api/engagements/eng-zy01/infrastructure") && init?.method === "POST") return Promise.resolve(jsonResponse({ engagement }));
      if (url.endsWith("/api/engagements/eng-zy01/revisions") && init?.method === "POST") return Promise.resolve(jsonResponse({ revision: { id: plan.revisionId, engagementId: engagement.id, revisionNumber: 1, status: "compiled", templateId: "standard-rti", inputParameters: {}, resolvedTopology: {}, runIntent: [], validationGates: validationGates() } }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans") && init?.method === "POST") return Promise.resolve(jsonResponse({ plan }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/plan-current/apply") && init?.method === "POST") return Promise.resolve(jsonResponse({ plan: { ...plan, status: "applying" }, job: pilotRunningJob(engagement.id) }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    fireEvent.change(await screen.findByLabelText("SSH allowed CIDRs"), { target: { value: "159.54.185.107/32, 160.34.86.0/23" } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));
    await waitFor(() => expect(screen.getByLabelText("Saved core Terraform plan")).toHaveTextContent("plan-current"));
    const review = screen.getByLabelText("Infrastructure plan review");
    expect(review).toHaveTextContent("Sketch state mode");
    expect(review).toHaveTextContent("Provider-keyed pilot");
    expect(review).toHaveTextContent(`Saved plan: ${mismatch ? "Standard" : "Provider-keyed pilot"}`);
    if (mixed) {
      const sketchAuthorization = screen.getByLabelText("Reviewed Sketch authorization");
      expect(sketchAuthorization).toHaveTextContent("linode image linode/ubuntu24.04");
      expect(sketchAuthorization).toHaveTextContent("digitalocean image digitalocean/ubuntu24.04");
      expect(sketchAuthorization).toHaveTextContent("Each provider has its own reviewed Sketch state and firewall");
    }
    if (mismatch) expect(screen.getByRole("alert")).toHaveTextContent("Plan state mode mismatch");
    fireEvent.change(screen.getByLabelText("Confirmation token"), { target: { value: "mutate-barragan-testing" } });
    const deploy = screen.getByRole("button", { name: "Deploy" });
    if (eligible && !mismatch) {
      expect(deploy).toBeEnabled();
      fireEvent.click(deploy);
      await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/deployment-plans/plan-current/apply"))).toBe(true));
    } else {
      expect(deploy).toBeDisabled();
      expect(fetchMock.mock.calls.some(([input]) => String(input).endsWith("/deployment-plans/plan-current/apply"))).toBe(false);
    }
  });

  it("polls a preparing output-only plan to ready without classifying it as no changes", async () => {
    const cidrs = ["160.34.90.0/23"];
    const outputPlan = corePlanReviewFixture({
      id: "plan-output-only",
      revisionId: "rev-output-only",
      counts: { add: 0, update: 0, replace: 0, remove: 0, read: 0, output: 1 },
      resourceChanges: [{ action: "output", address: "output.homebase_public_ip", type: "Terraform output", provider: "terraform", displayName: "Homebase public IP", group: "Outputs" }],
      sshSourceCidrs: cidrs,
      reviewedConfiguration: {
        ...corePlanReviewFixture().reviewedConfiguration,
        sshSourceCidrs: cidrs
      },
      sanitizedTextKind: "terraform_plan",
      sanitizedText: "Changes to Outputs:\n  ~ homebase_public_ip = (known after apply)"
    });
    let planReads = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [{ id: "standard-rti", name: "Standard RTI", version: "1", description: "Baseline", defaultNodeGroups: [], supportedProviders: ["oci"] }] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ templateId: "standard-rti" })] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.includes("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.includes("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: emptyOperationsOverview("") }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/current")) return Promise.resolve(jsonResponse({ plan: null }));
      if (url.endsWith("/api/engagements/eng-zy01/infrastructure") && init?.method === "POST") return Promise.resolve(jsonResponse({ engagement: engagementSummary({ templateId: "standard-rti" }) }));
      if (url.endsWith("/api/engagements/eng-zy01/revisions") && init?.method === "POST") return Promise.resolve(jsonResponse({ revision: { id: "rev-output-only", engagementId: "eng-zy01", revisionNumber: 1, status: "compiled", templateId: "standard-rti", inputParameters: {}, resolvedTopology: {}, runIntent: [], validationGates: validationGates() } }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans") && init?.method === "POST") return Promise.resolve(jsonResponse({ plan: { ...outputPlan, status: "preparing", stage: "terraform_plan" } }));
      if (url.endsWith("/api/engagements/eng-zy01/deployment-plans/plan-output-only")) {
        planReads += 1;
        return Promise.resolve(jsonResponse({ plan: outputPlan }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    fireEvent.change(await screen.findByLabelText("SSH allowed CIDRs"), { target: { value: cidrs[0] } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare Infrastructure Plan" }));

    await waitFor(() => expect(screen.getByText("Preparing Infrastructure Plan")).toBeInTheDocument());
    await waitFor(() => expect(planReads).toBeGreaterThan(0), { timeout: 4000 });
    await waitFor(() => expect(screen.getByLabelText("Terraform action counts")).toHaveTextContent("Output1"));
    expect(screen.queryByText("No core changes.")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Outputs resource changes")).toHaveTextContent("OutputHomebase public IP");
    fireEvent.click(screen.getByText("Advanced Terraform evidence"));
    expect(screen.getByLabelText("Sanitized Terraform plan")).toHaveTextContent("Changes to Outputs");
    expect(screen.getByLabelText("Guided deployment confirmation")).toBeInTheDocument();
  });

  it("observes pending durable chains from running infrastructure without initiating deployment", async () => {
    const compiledRevision = compiledSketchRevision("rev-zy01-001", [
      sketchChainInput("proxy01-chain-1", "proxy01", "linode", "us-sea", "linode", "us-sea"),
      sketchChainInput("proxy02-chain-1", "proxy02", "digitalocean", "sfo3", "digitalocean", "sfo3")
    ]);
    const durableChains = [
      sketchChainRecordFromBody("proxy01-us-sea-01", compiledRevision.inputParameters.sketchChains[0]),
      sketchChainRecordFromBody("proxy02-sfo3-01", compiledRevision.inputParameters.sketchChains[1])
    ];
    const coreJob = {
      ...pilotRunJob("eng-zy01"),
      input: {
        ...pilotRunJob("eng-zy01").input,
        postCoreSketchContinuationEligible: true,
        pendingSketchChainIds: durableChains.map((chain) => chain.chainId)
      }
    };
    let sketchChainReads = 0;
    const refreshedChains = new Set<string>();
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ activeRevision: compiledRevision.id })] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/workspace")) {
        return Promise.resolve(jsonResponse({ workspace: engagementWorkspace("eng-zy01") }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001")) {
        return Promise.resolve(jsonResponse({ job: coreJob }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ job: coreJob }));
      }
      if (url.includes("/api/provider-catalog/sketch?provider=linode")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      }
      if (url.includes("/api/provider-catalog/sketch?provider=digitalocean")) {
        return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/revisions")) {
        return Promise.resolve(jsonResponse({ revisions: [compiledRevision] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) {
        sketchChainReads += 1;
        return Promise.resolve(jsonResponse({
          sketchChains: durableChains.map((chain, index) =>
            sketchChainReads === 1
              ? chain
              : {
                  ...chain,
                  status: refreshedChains.has(chain.chainId) ? "deployed" : "deploying",
                  deployJobId: index === 0 ? "job-sketch-linode" : "job-sketch-digitalocean"
                }
          )
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-us-sea-01/deploy") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          chain: { ...sketchChainRecordFromBody("proxy01-us-sea-01", { assignedProxy: "proxy01", middleProvider: "linode", middleRegion: "us-sea", middleSize: "g6-nanode-1", edgeProvider: "linode", edgeRegion: "us-sea", edgeSize: "g6-nanode-1" }), status: "deploying", deployJobId: "job-sketch-linode" },
          job: sketchDeployJob("job-sketch-linode", "linode_sketch_deploy", "proxy01-us-sea-01", "proxy01")
        }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy02-sfo3-01/deploy") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          chain: { ...sketchChainRecordFromBody("proxy02-sfo3-01", { assignedProxy: "proxy02", middleProvider: "digitalocean", middleRegion: "sfo3", middleSize: "s-1vcpu-1gb", edgeProvider: "digitalocean", edgeRegion: "sfo3", edgeSize: "s-1vcpu-1gb" }), status: "deploying", deployJobId: "job-sketch-digitalocean" },
          job: sketchDeployJob("job-sketch-digitalocean", "digitalocean_sketch_deploy", "proxy02-sfo3-01", "proxy02")
        }));
      }
      if (url.endsWith("/api/jobs/job-sketch-linode")) {
        return Promise.resolve(jsonResponse({ job: { ...sketchDeployJob("job-sketch-linode", "linode_sketch_deploy", "proxy01-us-sea-01", "proxy01"), status: "succeeded" } }));
      }
      if (url.endsWith("/api/jobs/job-sketch-digitalocean")) {
        return Promise.resolve(jsonResponse({ job: { ...sketchDeployJob("job-sketch-digitalocean", "digitalocean_sketch_deploy", "proxy02-sfo3-01", "proxy02"), status: "succeeded" } }));
      }
      if (url.includes("/api/engagements/eng-zy01/sketch-chains/") && url.endsWith("/refresh") && init?.method === "POST") {
        const chainId = url.split("/").at(-2) ?? "";
        refreshedChains.add(chainId);
        const chain = durableChains.find((candidate) => candidate.chainId === chainId);
        return Promise.resolve(jsonResponse({ sketchChain: { ...(chain ?? durableChains[0]), status: "deployed" } }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText("Current Core Infrastructure")).toBeInTheDocument());
    await waitFor(() =>
      expect(screen.getByText("proxy01 -> middle -> edge-01 linode/us-sea · deployed")).toBeInTheDocument()
    );
    expect(fetchMock).toHaveBeenCalledWith("/api/jobs/job-sketch-linode");

    expect(fetchMock.mock.calls.some(([input, init]) =>
      String(input).endsWith("/api/engagements/eng-zy01/sketch-chains") && init?.method === "POST"
    )).toBe(false);
    expect(fetchMock.mock.calls.some(([input, init]) =>
      String(input).includes("/api/engagements/eng-zy01/sketch-chains/") &&
      String(input).endsWith("/deploy") && init?.method === "POST"
    )).toBe(false);
  });




  it("keeps aborted and destroyed sketch history out of the live lifecycle while retaining failed chains for recovery", async () => {
    let chains = [
      sketchChainRecord("proxy01-sea-02"),
      { ...sketchChainRecord("proxy01-sea-destroyed"), status: "destroyed" },
      {
        ...sketchChainRecord("proxy01-sea-failed"),
        status: "failed",
        deployJobId: "job-retained-bootstrap",
        nodes: [{ provider: "linode", providerInstanceId: "1111", role: "middle" }]
      }
    ];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) {
        return Promise.resolve(jsonResponse({ sketchChains: chains }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-sea-02/cancel") && init?.method === "POST") {
        chains = [{ ...chains[0], status: "aborted" }, ...chains.slice(1)];
        return Promise.resolve(jsonResponse({ sketchChain: chains[0] }));
      }
      if (url.endsWith("/api/jobs/job-retained-bootstrap")) {
        return Promise.resolve(jsonResponse({ job: failedBootstrapJob("job-retained-bootstrap", "proxy01-sea-failed") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    const lifecycle = await screen.findByLabelText("Live sketch chain lifecycle");
    await waitFor(() => expect(lifecycle).toHaveTextContent("proxy01-sea-02"));
    expect(within(lifecycle).getByText("2 chains · ready")).toBeInTheDocument();
    expect(within(lifecycle).queryByText("proxy01-sea-destroyed")).not.toBeInTheDocument();
    expect(within(lifecycle).getByText("proxy01-sea-failed")).toBeInTheDocument();
    await waitFor(() =>
      expect(within(lifecycle).getByText(/failed bootstrap parent job-retained-bootstrap/)).toBeInTheDocument()
    );
    expect(within(lifecycle).getByRole("button", { name: "Retry Bootstrap" })).toBeEnabled();
    expect(within(lifecycle).getByRole("button", { name: "Deploy New Chain" })).toBeEnabled();

    fireEvent.click(within(lifecycle).getByRole("button", { name: "Cancel" }));
    const confirmation = within(lifecycle).getByRole("group", { name: "proxy01-sea-02 cancel confirmation" });
    expect(within(confirmation).getByRole("button", { name: "Confirm Cancel" })).toBeDisabled();
    fireEvent.change(within(confirmation).getByLabelText("proxy01-sea-02 cancel phrase"), {
      target: { value: "cancel-proxy01-sea-02" }
    });
    fireEvent.click(within(confirmation).getByRole("button", { name: "Confirm Cancel" }));

    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/sketch-chains/proxy01-sea-02/cancel",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ confirmation: "cancel-proxy01-sea-02" })
        })
      )
    );
    await waitFor(() => expect(within(lifecycle).queryByRole("heading", { name: "proxy01-sea-02" })).not.toBeInTheDocument());
    expect(within(lifecycle).getByText("1 chains · ready")).toBeInTheDocument();
  });

  it("keeps retained bootstrap recovery available after navigation and posts only the existing chain endpoint", async () => {
    const retainedChain = {
      ...sketchChainRecord("proxy01-sea-retained"),
      status: "failed",
      deployJobId: "job-retained-bootstrap",
      middleRegion: "us-ord",
      edgeRegion: "us-ord",
      edges: [{ id: "edge-01", provider: "linode", region: "us-ord", size: "g6-nanode-1" }],
      terraformWorkingDirectory: "/var/lib/barragan/sketch/retained",
      nodes: [
        { provider: "linode", providerInstanceId: "1111", role: "middle" },
        { provider: "linode", providerInstanceId: "2222", role: "edge" }
      ]
    };
    const operations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      teardownJob: null
    };
    const failedRetryJob = failedBootstrapJob("job-retained-bootstrap", retainedChain.chainId);
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/api/provider-catalog/sketch?provider=linode")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
      if (url.includes("/api/provider-catalog/sketch?provider=digitalocean")) return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) return Promise.resolve(jsonResponse({ sketchChains: [retainedChain] }));
      if (url.endsWith("/api/jobs/job-retained-bootstrap")) return Promise.resolve(jsonResponse({ job: failedRetryJob }));
      if (url.endsWith(`/api/engagements/eng-zy01/sketch-chains/${retainedChain.chainId}/deploy`) && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ chain: retainedChain, job: failedRetryJob }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Manage Running Infrastructure" })).toBeInTheDocument();
    let lifecycle = await screen.findByLabelText("Live sketch chain lifecycle");
    expect(within(lifecycle).getByRole("button", { name: "Retry Bootstrap" })).toBeEnabled();

    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    await screen.findByLabelText("Engagement operations dashboard");
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    lifecycle = await screen.findByLabelText("Live sketch chain lifecycle");
    fireEvent.click(within(lifecycle).getByRole("button", { name: "Retry Bootstrap" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      `/api/engagements/eng-zy01/sketch-chains/${retainedChain.chainId}/deploy`,
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining('"retryBootstrapOnly":true')
      })
    ));
    const deploymentMutations = fetchMock.mock.calls.filter(([input, init]) =>
      init?.method === "POST" && String(input).endsWith("/deploy")
    );
    expect(deploymentMutations).toHaveLength(1);
    expect(deploymentMutations[0][0]).toBe(`/api/engagements/eng-zy01/sketch-chains/${retainedChain.chainId}/deploy`);
  });

  it.each(["missing job", "wrong status", "missing marker", "wrong marker", "timed out", "unproved termination"])(
  "does not label or submit an ineligible failed chain with %s",
  async (parentCase) => {
    const failedChain = {
      ...sketchChainRecord("proxy01-sea-incomplete"),
      status: "failed",
      deployJobId: "job-ineligible-bootstrap",
      nodes: [{ provider: "linode", providerInstanceId: "1111", role: "middle" }]
    };
    const baseJob = failedBootstrapJob(failedChain.deployJobId, failedChain.chainId);
    const needsReview = parentCase === "timed out" || parentCase === "unproved termination";
    const invalidJob = needsReview
      ? { ...baseJob, events: [...baseJob.events, { sequence: 3, level: "error", message: "local bootstrap stopped; remote work may remain", data: {
          bootstrap: "reconciliation_required", reconciliationRequired: true,
          timedOut: parentCase === "timed out", localQuiescenceUnproved: parentCase === "unproved termination"
        } }] }
      : parentCase === "wrong status"
      ? { ...baseJob, status: "succeeded" }
      : parentCase === "missing marker"
        ? { ...baseJob, events: [] }
        : { ...baseJob, events: [{ sequence: 1, level: "error", message: "bootstrap", data: { bootstrap: "starting" } }] };
    const operations = {
      ...operationsOverview(""),
      lifecycle: { state: "active", label: "Active", attentionRequired: false, terminal: false },
      teardownJob: null
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/api/provider-catalog/sketch?")) return Promise.resolve(jsonResponse({ catalog: providerCatalog(url.includes("digitalocean") ? "digitalocean" : "linode") }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) return Promise.resolve(jsonResponse({ sketchChains: [failedChain] }));
      if (url.endsWith(`/api/jobs/${failedChain.deployJobId}`)) {
        return parentCase === "missing job"
          ? Promise.reject(new Error("job missing"))
          : Promise.resolve(jsonResponse({ job: invalidJob }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    const lifecycle = await screen.findByLabelText("Live sketch chain lifecycle");
    await waitFor(() => expect(lifecycle).toHaveTextContent(needsReview ? "reconciliation is required before retrying" : "no complete retained bootstrap record"));
    if (parentCase === "unproved termination") expect(within(lifecycle).getByRole("button", { name: "Tear Down Chain" })).toBeDisabled();
    if (parentCase === "timed out") expect(within(lifecycle).getByRole("button", { name: "Tear Down Chain" })).toBeEnabled();
    expect(within(lifecycle).queryByRole("button", { name: "Retry Bootstrap" })).not.toBeInTheDocument();
    expect(within(lifecycle).queryByRole("button", { name: "Deploy New Chain" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input, init]) => init?.method === "POST" && String(input).endsWith("/deploy"))).toBe(false);
  });

  it("shows asynchronous sketch teardown progress from running infrastructure and reopens the log", async () => {
    let chain = {
      ...sketchChainRecord("proxy01-sea-01"),
      status: "deployed",
      deployJobId: "job-linode-deploy",
      nodes: [{ provider: "linode", providerInstanceId: "1111", role: "middle", hostname: "middle-zy01", status: "deployed" }]
    };
    const runningJob = sketchTeardownJob("running");
    const completedJob = sketchTeardownJob("succeeded");
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) {
        return Promise.resolve(jsonResponse({ sketchChains: [chain] }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-sea-01/teardown") && init?.method === "POST") {
        chain = { ...chain, status: "tearing_down", teardownJobId: runningJob.id };
        return Promise.resolve(jsonResponse({ chain, job: runningJob }));
      }
      if (url.endsWith(`/api/jobs/${runningJob.id}`)) {
        return Promise.resolve(jsonResponse({ job: completedJob }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-sea-01/refresh") && init?.method === "POST") {
        chain = { ...chain, status: "destroyed", nodes: [] };
        return Promise.resolve(jsonResponse({ sketchChain: chain }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    const lifecycle = await screen.findByLabelText("Live sketch chain lifecycle");
    fireEvent.click(within(lifecycle).getByRole("button", { name: "Tear Down Chain" }));
    const confirmation = within(lifecycle).getByRole("group", { name: "proxy01-sea-01 teardown confirmation" });
    fireEvent.change(within(confirmation).getByLabelText("proxy01-sea-01 teardown phrase"), {
      target: { value: "teardown-proxy01-sea-01" }
    });
    fireEvent.click(within(confirmation).getByRole("button", { name: "Confirm Chain Tear Down" }));

    const consolePanel = await screen.findByLabelText("Sketch teardown progress");
    expect(consolePanel).toHaveTextContent("Linode sketch teardown started");
    await waitFor(() => expect(consolePanel).toHaveTextContent("terraform cleanup verified"));
    fireEvent.click(within(consolePanel).getByRole("button", { name: "Close" }));
    expect(screen.queryByLabelText("Sketch teardown progress")).not.toBeInTheDocument();
    fireEvent.click(within(lifecycle).getByRole("button", { name: "Log" }));
    expect(screen.getByLabelText("Sketch teardown progress")).toHaveTextContent("job-sketch-teardown");
  });

  it("directs incomplete sketch chain state to Provider Tracking recovery", async () => {
    const stuckChain = { ...sketchChainRecord("proxy01-sea-01"), status: "deploying", deployJobId: "job-stale", nodes: [] };
    const overview = { ...operationsOverview(""), providerFindings: [orphanCandidateFixture()] };
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
        if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
        if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
        if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
          return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
        }
        if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [stuckChain] }));
        if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: overview }));
        return Promise.resolve(jsonResponse({}));
      })
    );

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText(/Provider inventory still sees infrastructure/)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Review Provider Recovery" }));
    expect(await screen.findByLabelText("Provider tracking findings")).toHaveTextContent("homebase-or01");
  });

  it("stops and starts deployed sketch chains with provider power confirmations", async () => {
    let chains = [
      {
        ...sketchChainRecord("proxy01-sea-01"),
        status: "deployed",
        deployJobId: "job-linode-deploy",
        nodes: [
          { provider: "linode", providerInstanceId: "1111", role: "middle", hostname: "middle-zy01", status: "deployed" },
          { provider: "linode", providerInstanceId: "2222", role: "edge", hostname: "edge-zy01", status: "deployed" }
        ]
      }
    ];
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains") && !init?.method) {
        return Promise.resolve(jsonResponse({ sketchChains: chains }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-sea-01/stop") && init?.method === "POST") {
        chains = [{ ...chains[0], status: "stopped", nodes: chains[0].nodes.map((node) => ({ ...node, status: "stopped" })) }];
        return Promise.resolve(jsonResponse({ chain: chains[0], job: sketchPowerJob("sketch_chain_stop") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains/proxy01-sea-01/start") && init?.method === "POST") {
        chains = [{ ...chains[0], status: "deployed", nodes: chains[0].nodes.map((node) => ({ ...node, status: "deployed" })) }];
        return Promise.resolve(jsonResponse({ chain: chains[0], job: sketchPowerJob("sketch_chain_start") }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByLabelText("Live sketch chain lifecycle")).toHaveTextContent("proxy01-sea-01"));
    expect(screen.getByText(/Stop and start use provider power APIs only/)).toBeInTheDocument();

    expect(screen.getByRole("button", { name: "Stop Nodes" })).toBeDisabled();
    fireEvent.change(screen.getByLabelText("proxy01-sea-01 stop phrase"), {
      target: { value: "stop-proxy01-sea-01" }
    });
    expect(screen.getByRole("button", { name: "Stop Nodes" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Stop Nodes" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/sketch-chains/proxy01-sea-01/stop",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ confirmation: "stop-proxy01-sea-01" })
        })
      )
    );
    await waitFor(() => expect(screen.getByText(/stopped through provider power operation/)).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("proxy01-sea-01 start phrase"), {
      target: { value: "start-proxy01-sea-01" }
    });
    expect(screen.getByRole("button", { name: "Start Nodes" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Start Nodes" }));
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/engagements/eng-zy01/sketch-chains/proxy01-sea-01/start",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ confirmation: "start-proxy01-sea-01" })
        })
      )
    );
    await waitFor(() => expect(screen.getByText(/started through provider power operation/)).toBeInTheDocument());
  });

  it("loads a persisted pilot job and resumes it in the engagement workspace without starting a new run", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.includes("/api/jobs?")) {
        return Promise.resolve(jsonResponse({
          jobs: [
            {
              id: "job-pilot-001",
              action: "pilot_standard_rti_guarded_execute",
              status: "succeeded",
              target: "oci_compartment:ocid1.compartment.oc1..testing",
              createdAt: "2026-06-01T12:00:00+00:00"
            }
          ],
          pagination: { total: 1, limit: 50, offset: 0, hasMore: false }
        }));
      }
      if (url.endsWith("/api/jobs/job-pilot-001")) {
        return Promise.resolve(jsonResponse({ job: pilotRunJob("eng-zy01") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001")) {
        return Promise.resolve(jsonResponse({ job: pilotRunJob("eng-zy01") }));
      }
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Jobs" }));
    fireEvent.click(await screen.findByRole("button", { name: "Select job job-pilot-001" }));

    await waitFor(() => expect(screen.getByText("Job detail")).toBeInTheDocument());
    expect(screen.getByText("pilot Standard RTI run finished")).toBeInTheDocument();
    expect(screen.getAllByText("workspaceDir=/tmp/barragan-ui-test").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("button", { name: "Load In Engagement" }));

    await waitFor(() => expect(screen.getByRole("heading", { name: "Manage Running Infrastructure" })).toBeInTheDocument());
    expect(screen.getByText("Current Core Infrastructure")).toBeInTheDocument();
    expect(screen.getAllByText("job-pilot-001").length).toBeGreaterThan(0);
    expect(screen.getByText("pending_operator_teardown")).toBeInTheDocument();
    expect(screen.getAllByText("ssh homebase-zy01").length).toBeGreaterThan(0);
    expect(screen.getByLabelText("Manage running infrastructure")).toHaveTextContent("Live sketch chain lifecycle");
    expect(fetchMock).not.toHaveBeenCalledWith(
      "/api/orchestrator/barragan-testing/pilot-standard-rti/runs",
      expect.objectContaining({ method: "POST" })
    );
  });

  it("shows verified destroyed infrastructure as history despite retained deployed hosts and core output", async () => {
    const operations = {
      ...operationsOverview(""),
      lifecycle: { state: "destroyed", label: "Destroyed", attentionRequired: false, terminal: true },
      teardownJob: { id: "job-cleanup", action: "engagement_comprehensive_teardown", status: "succeeded", recoveryState: "complete" }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001")) return Promise.resolve(jsonResponse({ job: pilotRunJob("eng-zy01") }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Infrastructure Destroyed" })).toBeInTheDocument();
    const history = screen.getByLabelText("Historical core infrastructure");
    expect(await within(history).findByText("job-pilot-001")).toBeInTheDocument();
    expect(history).toHaveTextContent("pending_operator_teardown");
    expect(history).toHaveTextContent("before verified cleanup");
    expect(screen.getByLabelText("Historical connection details")).toHaveTextContent("ssh homebase-zy01");
    expect(screen.queryByLabelText("Current core infrastructure")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Manage running infrastructure")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Live sketch chain lifecycle")).not.toBeInTheDocument();
    for (const name of ["Tear Down Infrastructure", "Retry Tear Down", "Start Instances", "Stop Instances", "Re-Deploy Core Infrastructure", "Prepare Infrastructure Plan", "Deploy"]) {
      expect(screen.queryByRole("button", { name, exact: true })).not.toBeInTheDocument();
    }
    fireEvent.click(within(history).getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/api/engagements/eng-zy01/operations")).length).toBeGreaterThan(2));
    fireEvent.click(screen.getByRole("button", { name: "History", exact: true }));
    expect(await screen.findByLabelText("Core deployment history")).toHaveTextContent("pilot Standard RTI run finished");
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === "POST")).toBe(false);
  });

  it("keeps infrastructure actions hidden until authoritative clean Operations state resolves", async () => {
    let resolveOperations!: (response: Response) => void;
    const operationsResponse = new Promise<Response>((resolve) => {
      resolveOperations = resolve;
    });
    const cleanOperations = {
      ...operationsOverview(""),
      lifecycle: { state: "not_deployed", label: "Not deployed", attentionRequired: false, terminal: false },
      activeJob: null,
      coreJob: null,
      teardownJob: null,
      coreInfrastructure: [],
      sketchInfrastructure: []
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return operationsResponse;
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Loading infrastructure state" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Prepare Infrastructure Plan" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Add proxy.* Chain/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Re-Deploy Core Infrastructure" })).not.toBeInTheDocument();

    resolveOperations(jsonResponse({ operations: cleanOperations }));
    expect(await screen.findByRole("button", { name: "Prepare Infrastructure Plan" })).toBeInTheDocument();
  });

  it("keeps infrastructure mutations unavailable when Operations loading fails", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.reject(new Error("operations unavailable"));
      if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) return Promise.resolve(jsonResponse({ sketchChains: [] }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Infrastructure state unavailable" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Prepare Infrastructure Plan" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Add proxy.* Chain/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Re-Deploy Core Infrastructure" })).not.toBeInTheDocument();
  });

  it("navigates from an exact comprehensive teardown job to cleanup recovery without mutation", async () => {
    const parentId = "job-comprehensive-shortcut";
    const parent = comprehensiveRecoveryJob(parentId);
    const operations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      coreInfrastructure: [],
      teardownJob: { id: parentId, action: "engagement_comprehensive_teardown", status: "failed", recoveryState: "recoverable", createdAt: "2026-06-03T00:00:00Z", finishedAt: "2026-06-03T00:01:00Z" }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.includes("/api/jobs?")) return Promise.resolve(jsonResponse({ jobs: [{ id: parentId, action: "engagement_comprehensive_teardown", status: "failed", target: "engagement:eng-zy01", createdAt: "2026-06-03T00:00:00Z" }], pagination: { total: 1, limit: 50, offset: 0, hasMore: false } }));
      if (url.endsWith(`/api/jobs/${parentId}`)) return Promise.resolve(jsonResponse({ job: parent }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}`)) return Promise.resolve(jsonResponse({ job: parent }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Jobs" }));
    fireEvent.click(await screen.findByRole("button", { name: `Select job ${parentId}` }));
    fireEvent.click(await screen.findByRole("button", { name: "Resume Cleanup" }));

    expect(await screen.findByRole("heading", { name: "Recover Infrastructure Cleanup" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry Tear Down" })).toBeEnabled();
    expect(screen.queryByLabelText("Live sketch chain lifecycle")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Add proxy.* Chain/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry Bootstrap" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Deploy New Chain" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Tear Down Chain" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Re-Deploy Core Infrastructure" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).includes("/teardown") && init?.method === "POST")).toBe(false);
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).includes("/deployment-plans") && init?.method === "POST")).toBe(false);
  });

  it.each([
    ["destroy_plans", "awaiting_both_destroy_plans", 0, "Review both saved provider destroy plans", "queued"],
    ["linode_absence", "plans_sealed", 1, "Destroy owned infrastructure and prove exact absence", "queued"],
    ["lifecycle_reconciliation", "plans_sealed", 8, "Reconcile engagement lifecycle", "queued"],
    ["core_destroy_apply", "plans_sealed", 4, "Destroy owned infrastructure and prove exact absence", "running"]
  ] as const)("opens published mixed %s progress in the recovery console", async (phase, inputPhase, completed, currentStep, status) => {
    const { parent, operations, engagement } = publishedTeardownFixture({ phase, inputPhase, completed, status });
    const parentId = parent.id;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ ...engagement, lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith(`/api/engagements/${engagement.id}/operations`)) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}`)) return Promise.resolve(jsonResponse({ job: parent }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Infrastructure teardown in progress" })).toBeInTheDocument();
    expect(screen.queryByText("Cleanup recovery unavailable")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Teardown worker progress")).toHaveTextContent("Worker claim is active");
    expect(screen.getByLabelText("Teardown worker progress")).toHaveTextContent(parent.activeChild?.message ?? "Waiting for the next recorded teardown step.");
    expect(screen.queryByLabelText("Current core infrastructure")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open Console" }));
    expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent(currentStep);
    expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("Elapsed: 2m");
    expect(screen.getByLabelText("Infrastructure teardown console")).not.toHaveTextContent("Last activity: 0s ago");
    await waitFor(() => expect(screen.getByRole("button", { name: "Tear Down Infrastructure" })).toBeDisabled());
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).includes("/teardown") && init?.method === "POST")).toBe(false);
  });

  it("does not offer Retry for a failed published mixed cleanup parent", async () => {
    const parentId = "job-provider-keyed-mixed-published-cleanup-pilot-001";
    const operations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      coreInfrastructure: [],
      teardownJob: { id: parentId, action: "provider_keyed_mixed_published_cleanup", status: "failed",
        recoveryState: "blocked", createdAt: "2026-10-19T00:00:00Z", finishedAt: null }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}`)) return Promise.resolve(jsonResponse({
        job: { ...comprehensiveRecoveryJob(parentId), action: "provider_keyed_mixed_published_cleanup" }
      }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cleanup recovery unavailable");
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  });

  it("does not offer Resume Cleanup for a cross-engagement teardown detail", async () => {
    const parentId = "job-cross-engagement";
    const parent = { ...comprehensiveRecoveryJob(parentId), targetId: "eng-other" };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.includes("/api/jobs?")) return Promise.resolve(jsonResponse({ jobs: [{ id: parentId, action: "engagement_comprehensive_teardown", status: "failed", target: "engagement:eng-zy01", createdAt: "2026-06-03T00:00:00Z" }], pagination: { total: 1, limit: 50, offset: 0, hasMore: false } }));
      if (url.endsWith(`/api/jobs/${parentId}`)) return Promise.resolve(jsonResponse({ job: parent }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Jobs" }));
    fireEvent.click(await screen.findByRole("button", { name: `Select job ${parentId}` }));
    await screen.findByRole("heading", { name: "Job detail" });
    expect(screen.queryByRole("button", { name: "Resume Cleanup" })).not.toBeInTheDocument();
  });

  it("restores the active engagement run from operations without loading global jobs", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: operationsOverview("") }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001")) {
        return Promise.resolve(jsonResponse({ job: pilotRunJob("eng-zy01") }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText("Current Core Infrastructure")).toBeInTheDocument());

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001"
    );
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/jobs"))).toBe(false);
    expect(screen.getAllByText("job-pilot-001").length).toBeGreaterThan(0);

    const operationsCallsBeforeRefresh = fetchMock.mock.calls.filter(([input]) =>
      String(input).endsWith("/api/engagements/eng-zy01/operations")
    ).length;
    fireEvent.click(within(screen.getByLabelText("Current core infrastructure")).getByRole("button", { name: "Refresh" }));
    await waitFor(() =>
      expect(fetchMock.mock.calls.filter(([input]) =>
        String(input).endsWith("/api/engagements/eng-zy01/operations")
      ).length).toBeGreaterThan(operationsCallsBeforeRefresh)
    );
  });

  it("keeps cleanup-not-verified core infrastructure visible for browser teardown retry", async () => {
    const failedJob = pilotCleanupNotVerifiedJob("eng-zy01");
    const recoveryOperations = operationsOverview("");
    recoveryOperations.activeJob.status = "failed";
    recoveryOperations.coreInfrastructure = recoveryOperations.coreInfrastructure.map((host) => ({
      ...host,
      status: "cleanup_not_verified",
      lifecycleState: "cleanup_not_verified",
      lastKnown: true
    }));
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      }
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) {
        return Promise.resolve(jsonResponse({ operations: recoveryOperations }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001")) {
        return Promise.resolve(jsonResponse({ job: failedJob }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByText("Current Core Infrastructure")).toBeInTheDocument());

    expect(screen.getByRole("heading", { name: "Manage Running Infrastructure" })).toBeInTheDocument();
    expect(screen.getAllByText("cleanup_not_verified").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Retry Tear Down" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Deploy" })).not.toBeInTheDocument();
  });

  it("discovers the exact comprehensive teardown parent with zero hosts and retries the same snapshot", async () => {
    const parentId = "job-comprehensive-recovery";
    const failedParent = comprehensiveRecoveryJob(parentId);
    failedParent.input.scopeSnapshot.chains = [{
      chainId: "proxy01-pending", assignedProxy: "proxy01", status: "pending", deployJobId: "", alreadyClean: true,
      outboundChannelIds: [], middle: { provider: "linode", region: "us-east" },
      edges: [{ id: "edge-1", provider: "digitalocean", region: "nyc3" }]
    }];
    const recoveryOperations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      coreInfrastructure: [],
      sketchInfrastructure: [],
      activeJob: { id: "job-newer-unrelated", action: "infra_orientation_refresh", status: "succeeded", createdAt: "2026-06-04T00:00:00Z", finishedAt: "2026-06-04T00:01:00Z" },
      teardownJob: { id: parentId, action: "engagement_comprehensive_teardown", status: "failed", recoveryState: "recoverable", createdAt: "2026-06-03T00:00:00Z", finishedAt: "2026-06-03T00:01:00Z" }
    };
    const preview = {
      snapshotId: "snapshot-immutable-1", engagementId: "eng-zy01", engagementName: "ZY01",
      confirmationPhrase: "teardown-ZY01", parentJobId: parentId,
      orderedScope: [{ id: "core", label: "Core infrastructure", items: [] }]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: recoveryOperations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: recoveryOperations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}/teardown`)) {
        if (init?.method === "POST") return Promise.resolve(jsonResponse({ job: { ...failedParent, status: "running" } }));
        return Promise.resolve(jsonResponse({ teardown: preview }));
      }
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}`)) return Promise.resolve(jsonResponse({ job: failedParent }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "Recover Infrastructure Cleanup" })).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Retry Tear Down" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Deploy" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry Tear Down" }));
    await screen.findByText(/Core infrastructure/);
    expect(fetchMock).toHaveBeenCalledWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}/teardown`);
    fireEvent.change(screen.getByLabelText("Confirm tear down phrase"), { target: { value: "teardown-ZY01" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm Tear Down" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      `/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}/teardown`,
      expect.objectContaining({ method: "POST", body: JSON.stringify({ confirmation: "teardown-ZY01", snapshotId: "snapshot-immutable-1" }) })
    ));
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).endsWith("/pilot-standard-rti/runs") && init?.method === "POST")).toBe(false);
    expect(fetchMock.mock.calls.some(([input, init]) => String(input).includes("/deployment-plans") && init?.method === "POST")).toBe(false);
  });

  it("renders accurate mixed zero-Apply scope before one confirmation", async () => {
    const core = pilotRunJob("eng-zy01");
    const operations = operationsOverview("");
    const preview = {
      snapshotId: "a".repeat(64), engagementId: "eng-zy01", engagementName: "ZY01",
      confirmationPhrase: "teardown-zy01", parentJobId: null,
      orderedScope: [
        { id: "sketch", label: "Confirm no Sketch Apply occurred", items: [
          { provider: "linode", savedPlanReceiptSha256: "b".repeat(64) },
          { provider: "digitalocean", savedPlanReceiptSha256: "c".repeat(64) }] },
        { id: "core", label: "Destroy core infrastructure", items: [{ proxyCount: 2 }] },
        { id: "inspector-verify", label: "Verify retired public endpoints", items: [{ targetCount: 3 }] },
        { id: "inspector-cleanup", label: "Destroy retained Inspector", items: [{ tracked: true }] }
      ]
    };
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}/teardown`)) return Promise.resolve(jsonResponse({ teardown: preview }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}`)) return Promise.resolve(jsonResponse({ job: core }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    }));

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Tear Down Infrastructure" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Tear Down Infrastructure" }));
    expect(await screen.findByText("linode then digitalocean saved plans; no Sketch Apply occurred")).toBeInTheDocument();
    expect(screen.getByText("Homebase and 2 proxies")).toBeInTheDocument();
    expect(screen.getByText("3 previously known public targets")).toBeInTheDocument();
    expect(screen.getByText("Tracked retained Inspector cleanup")).toBeInTheDocument();
    expect(screen.getByText(/No Sketch nodes were applied/)).toBeInTheDocument();
  });

  it("renders interrupted mixed provider classifications without invented chain topology", async () => {
    const core = pilotRunJob("eng-zy01");
    const operations = operationsOverview("");
    const preview = {
      snapshotId: "a".repeat(64), engagementId: "eng-zy01", engagementName: "ZY01",
      confirmationPhrase: "teardown-zy01", parentJobId: null,
      orderedScope: [
        { id: "sketch", label: "Destroy owned Sketch providers", items: [
          { provider: "linode", kind: "failed_absent", resourceCount: 0 },
          { provider: "digitalocean", kind: "unstarted", resourceCount: 0 }] },
        { id: "core", label: "Destroy core infrastructure", items: [{ proxyCount: 1 }] },
        { id: "inspector-verify", label: "Verify retired public endpoints", items: [{ targetCount: 2 }] },
        { id: "inspector-cleanup", label: "Destroy retained Inspector", items: [{ tracked: true }] }
      ]
    };
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}/teardown`)) return Promise.resolve(jsonResponse({ teardown: preview }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}`)) return Promise.resolve(jsonResponse({ job: core }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    }));
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Tear Down Infrastructure" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Tear Down Infrastructure" }));
    expect(await screen.findByText("linode: failed absent (0 owned resources); digitalocean: unstarted (0 owned resources)")).toBeInTheDocument();
    expect(screen.getByText("Homebase and 1 proxy")).toBeInTheDocument();
    expect(screen.getByText("2 previously known public targets")).toBeInTheDocument();
    expect(screen.getByText("Tracked retained Inspector cleanup")).toBeInTheDocument();
  });

  it("shows both owned provider scopes and Inspector resources in a published mixed teardown review", async () => {
    const core = pilotRunJob("eng-zy01");
    const operations = operationsOverview("");
    const preview = {
      snapshotId: "a".repeat(64), engagementId: "eng-zy01", engagementName: "ZY01",
      confirmationPhrase: "teardown-zy01", parentJobId: null,
      orderedScope: [
        { id: "provider-keyed", label: "Keyed provider resources", items: [
          { provider: "linode", resources: Array.from({ length: 6 }, () => ({})) },
          { provider: "digitalocean", resources: Array.from({ length: 6 }, () => ({})) }
        ] },
        { id: "core", label: "Core infrastructure", items: [{ proxyCount: 1 }] },
        { id: "inspector-cleanup", label: "Destroy retained Inspector", items: [
          { ownedProviderRecordIds: ["inspector-host", "inspector-firewall"] }
        ] }
      ]
    };
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}/teardown`)) return Promise.resolve(jsonResponse({ teardown: preview }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}`)) return Promise.resolve(jsonResponse({ job: core }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    }));

    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Tear Down Infrastructure" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Tear Down Infrastructure" }));
    expect(await screen.findByText("linode: 6 owned resources; digitalocean: 6 owned resources")).toBeInTheDocument();
    expect(screen.getByText("Homebase and 1 proxy")).toBeInTheDocument();
    expect(screen.getByText("2 owned Inspector resources")).toBeInTheDocument();
  });

  it("fails closed when cleanup required has no exact comprehensive parent", async () => {
    const recoveryOperations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      coreInfrastructure: [], teardownJob: null
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: recoveryOperations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: recoveryOperations }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("exact teardown parent");
    expect(screen.queryByRole("button", { name: "Deploy" })).not.toBeInTheDocument();
  });

  it("does not retry a succeeded incomplete comprehensive teardown even when core rows are stale", async () => {
    const recoveryOperations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      teardownJob: { id: "job-incomplete", action: "engagement_comprehensive_teardown", status: "succeeded", recoveryState: "blocked", createdAt: "2026-06-03T00:00:00Z", finishedAt: "2026-06-03T00:01:00Z" }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: recoveryOperations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: recoveryOperations }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cleanup recovery unavailable");
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  });

  it.each([
    ["duplicate edge IDs", (scope: Record<string, any>) => { scope.chains = [{
      chainId: "chain-1", assignedProxy: "proxy01", status: "deployed", deployJobId: "job-1", alreadyClean: false,
      outboundChannelIds: [], middle: { provider: "linode", region: "us-east" },
      edges: [
        { id: "edge-1", provider: "linode", region: "us-east" },
        { id: "edge-1", provider: "linode", region: "us-west" }
      ]
    }]; }],
    ["whitespace provider identity", (scope: Record<string, any>) => { scope.chains = [{
      chainId: "chain-1", assignedProxy: "proxy01", status: "deployed", deployJobId: "job-1", alreadyClean: false,
      outboundChannelIds: [], middle: { provider: " linode", region: "us-east" },
      edges: [{ id: "edge-1", provider: "linode", region: "us-east" }]
    }]; }],
    ["whitespace Inspector identity", (scope: Record<string, any>) => {
      scope.inspector = { ...scope.inspector, ownedProviderRecordIds: [" inspector-1"] };
    }]
  ])("does not expose Retry when a recoverable summary resolves to malformed nested scope: %s", async (_label, mutateScope) => {
    const parentId = "job-malformed-scope";
    const parent = comprehensiveRecoveryJob(parentId);
    parent.input.scopeSnapshot = { ...parent.input.scopeSnapshot };
    mutateScope(parent.input.scopeSnapshot as Record<string, any>);
    const operations = {
      ...operationsOverview(""),
      lifecycle: { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false },
      coreInfrastructure: [],
      teardownJob: { id: parentId, action: "engagement_comprehensive_teardown", status: "failed", recoveryState: "recoverable", createdAt: "2026-06-03T00:00:00Z", finishedAt: "2026-06-03T00:01:00Z" }
    };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary({ lifecycle: operations.lifecycle })] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations }));
      if (url.endsWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${parentId}`)) return Promise.resolve(jsonResponse({ job: parent }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cleanup recovery unavailable");
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  });

  it("shows comprehensive teardown failure detail and remaining resources", async () => {
    const failedJob = {
      ...comprehensiveRecoveryJob("job-pilot-001"),
      events: [
        ...pilotCleanupNotVerifiedJob("eng-zy01").events,
        { sequence: 30, level: "error", message: "engagement teardown requires cleanup", data: {
          detail: "Inspector address collides with a retired endpoint.",
          remainingOwnedResources: ["owned_provider_resource:inspector-1"],
          finalCleanupStatus: "cleanup_not_verified"
        } }
      ]
    };
    const recoveryOperations = operationsOverview("");
    recoveryOperations.activeJob.status = "failed";
    recoveryOperations.lifecycle = { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false };
    recoveryOperations.teardownJob = { id: "job-pilot-001", action: "engagement_comprehensive_teardown", status: "failed", recoveryState: "recoverable", createdAt: "2026-06-03T00:00:00Z", finishedAt: "2026-06-03T00:01:00Z" };
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith("/api/engagements/eng-zy01/operations")) return Promise.resolve(jsonResponse({ operations: recoveryOperations }));
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-pilot-001")) return Promise.resolve(jsonResponse({ job: failedJob }));
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Inspector address collides with a retired endpoint.");
    expect(screen.getByText("Remaining: owned_provider_resource:inspector-1")).toBeInTheDocument();
  });

  it("does not show a previous engagement deployment as done in a new engagement workspace", async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({
          engagements: [
            {
              ...engagementSummary(),
              id: "eng-ab01",
              name: "ab01"
            }
          ]
        }));
      }
      if (url.includes("/api/jobs?")) {
        return Promise.resolve(jsonResponse({
          jobs: [
            {
              id: "job-old-engagement",
              action: "pilot_standard_rti_guarded_execute",
              status: "succeeded",
              target: "oci_compartment:ocid1.compartment.oc1..testing",
              createdAt: "2026-06-01T12:00:00+00:00"
            }
          ],
          pagination: { total: 1, limit: 50, offset: 0, hasMore: false }
        }));
      }
      if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-old-engagement")) {
        return Promise.resolve(jsonResponse({ job: pilotRunJob("eng-old") }));
      }
      if (url.endsWith("/api/engagements/eng-ab01/operations")) {
        return Promise.resolve(jsonResponse({ operations: { ...emptyOperationsOverview(""), engagementId: "eng-ab01" } }));
      }
      if (url.includes("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness")) {
        return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));

    await waitFor(() => expect(screen.getByText("Deploy and watch progress")).toBeInTheDocument());
    expect(fetchMock).not.toHaveBeenCalledWith(
      "/api/orchestrator/barragan-testing/pilot-standard-rti/runs/job-old-engagement"
    );
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes("/api/jobs"))).toBe(false);
    expect(screen.queryByText("Run history")).not.toBeInTheDocument();
    expect(screen.queryByText("ssh homebase-pilot")).not.toBeInTheDocument();
    expect(screen.getByText("Deploy and watch progress")).toBeInTheDocument();
    expect(screen.queryByText("Deployment Console")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Open Console" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Terraform created the core OCI infrastructure/)).not.toBeInTheDocument();
  });

  it("polls a selected running job detail until it reaches a terminal state", async () => {
    let detailCalls = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [] }));
      }
      if (url.includes("/api/jobs?")) {
        return Promise.resolve(jsonResponse({
          jobs: [
            {
              id: "job-pilot-001",
              action: "pilot_standard_rti_guarded_execute",
              status: "running",
              target: "oci_compartment:ocid1.compartment.oc1..testing",
              createdAt: "2026-06-01T12:00:00+00:00"
            }
          ],
          pagination: { total: 1, limit: 50, offset: 0, hasMore: false }
        }));
      }
      if (url.endsWith("/api/jobs/job-pilot-001")) {
        detailCalls += 1;
        return Promise.resolve(jsonResponse({ job: detailCalls === 1 ? pilotRunningJob() : pilotRunJob() }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Jobs" }));
    fireEvent.click(await screen.findByRole("button", { name: "Select job job-pilot-001" }));

    await waitFor(() => expect(screen.getByText("pilot Standard RTI executor running")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("operator inspection ready")).toBeInTheDocument(), {
      timeout: 3000
    });

    expect(detailCalls).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText("succeeded").length).toBeGreaterThan(0);
  });

  it("configures and starts Inspector inspections from engagement settings", async () => {
    const observerJob = {
      id: "job-inspector-1",
      action: "inspector_inspection",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-ob01",
      requestedBy: "operator",
      input: {},
      artifactRefs: [],
      events: [
        { sequence: 1, level: "info", message: "inspection queued", data: {} },
        { sequence: 2, level: "info", message: "inspector host create succeeded", data: {} },
        { sequence: 3, level: "info", message: "inspection checks succeeded", data: {} },
        { sequence: 4, level: "info", message: "inspector host retained", data: {} }
      ]
    };
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) {
        return Promise.resolve(jsonResponse({ templates: [] }));
      }
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-ob01", name: "OB01", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: null }] }));
      }
      if (url.endsWith("/api/jobs")) {
        return Promise.resolve(jsonResponse({ jobs: [] }));
      }
      if (url.endsWith("/api/dashboard")) {
        return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      }
      if (url.includes("/api/provider-catalog/sketch?")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: sketchCatalogFixture(provider) }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-settings") && init?.method === "PATCH") {
        return Promise.resolve(jsonResponse({
          settings: observerSettingsFixture({ configured: true })
        }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-settings")) {
        return Promise.resolve(jsonResponse({
          settings: observerSettingsFixture({ configured: false })
        }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspections") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ job: observerJob, status: "succeeded" }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Engagement workspace sections" })).getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    await waitFor(() => expect(screen.getByLabelText("Inspector provider")).toBeInTheDocument());
    expect(screen.getByRole("heading", { name: "Inspector" })).toBeInTheDocument();
    expect(screen.getByLabelText("Inspector schedule time UTC")).toHaveValue("00:00");
    fireEvent.change(screen.getByLabelText("Inspector forbidden TCP ports"), { target: { value: "22, 2222" } });
    fireEvent.click(screen.getByText("Port Scan Profile"));
    fireEvent.click(screen.getByLabelText("Enable Inspector port scan"));
    fireEvent.change(screen.getByLabelText("Inspector port scan ports"), { target: { value: "2222" } });
    expect(screen.getByLabelText("Enable Inspector port scan")).toBeChecked();
    expect(screen.getByLabelText("Inspector port scan ports")).toHaveValue("2222");
    fireEvent.click(screen.getByRole("button", { name: "Save Inspector Settings" }));
    await waitFor(() => expect(screen.getByText("Inspector settings saved.")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Run Inspection Now" }));
    await waitFor(() => expect(screen.getByText("Inspection returned succeeded.")).toBeInTheDocument());
    expect(screen.getByText("Inspection checks passed.")).toBeInTheDocument();
    expect(screen.getByText("Inspector host retained.")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-ob01/inspections",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ triggerType: "manual", requestedBy: "operator" })
      })
    );
  });

  it("keeps a retained Inspector active after an inspection finding fails", async () => {
    const failedInspectionJob = {
      id: "job-inspector-finding",
      action: "inspector_inspection",
      status: "failed",
      targetType: "engagement",
      targetId: "eng-ob01",
      requestedBy: "operator",
      input: {},
      artifactRefs: [],
      events: [
        { sequence: 1, level: "info", message: "inspection queued", data: {} },
        { sequence: 2, level: "error", message: "inspection checks failed", data: {} },
        { sequence: 3, level: "info", message: "inspector host retained", data: {} }
      ]
    };
    let settingsReads = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-ob01", name: "OB01", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: null }] }));
      }
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: sketchCatalogFixture(provider) }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-settings")) {
        settingsReads += 1;
        return Promise.resolve(jsonResponse({
          settings: observerSettingsFixture(settingsReads > 1 ? {
            currentHost: { resourceId: "12345", publicIp: "198.51.100.25", status: "running" }
          } : {})
        }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspections") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ job: failedInspectionJob, status: "failed" }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Engagement workspace sections" })).getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    const inspector = await screen.findByRole("region", { name: "Inspector" });
    expect(within(inspector).getByText("not active")).toBeInTheDocument();
    fireEvent.click(within(inspector).getByRole("button", { name: "Run Inspection Now" }));

    await waitFor(() => expect(within(inspector).getByText("Inspection returned failed.")).toBeInTheDocument());
    await waitFor(() => expect(within(inspector).getByText("198.51.100.25")).toBeInTheDocument());
    expect(within(inspector).queryByText("not active")).not.toBeInTheDocument();
    expect(within(inspector).getByText("Inspection checks found a problem.")).toBeInTheDocument();
    expect(within(inspector).getByText("Inspector host retained.")).toBeInTheDocument();
    expect(settingsReads).toBeGreaterThanOrEqual(2);
  });

  it("prepares a missing continuous Inspector without pretending to run public checks", async () => {
    const readinessJob = {
      id: "job-inspector-ready",
      action: "inspector_readiness",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-ob01",
      requestedBy: "operator",
      input: {},
      artifactRefs: [],
      events: [{ sequence: 1, level: "info", message: "continuous Inspector readiness succeeded", data: {} }]
    };
    let settingsReads = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-ob01", name: "OB01", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: null }] }));
      }
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: sketchCatalogFixture(provider) }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-readiness") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ readiness: { required: true, ready: true, status: "ready", job: readinessJob } }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-settings")) {
        settingsReads += 1;
        return Promise.resolve(jsonResponse({ settings: observerSettingsFixture(settingsReads > 1 ? { currentHost: { publicIp: "198.51.100.25" } } : {}) }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Engagement workspace sections" })).getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    expect(await screen.findByRole("button", { name: "Verify / Prepare Inspector" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Verify / Prepare Inspector" }));

    await waitFor(() => expect(screen.getByText("Retained Inspector is ready for public checks.")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("198.51.100.25")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-ob01/inspector-readiness",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ requestedBy: "operator" }) })
    );
  });

  it("previews and destroys only retained Inspector resources from Settings", async () => {
    const cleanupJob = {
      id: "job-inspector-cleanup",
      action: "inspector_cleanup",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-ob01",
      requestedBy: "operator",
      input: { inspectorOnly: true },
      artifactRefs: [],
      events: [{ sequence: 1, level: "info", message: "inspector host cleanup verified", data: {} }]
    };
    let settingsReads = 0;
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) {
        return Promise.resolve(jsonResponse({ engagements: [{ id: "eng-ob01", name: "OB01", status: "planned", owner: "operator", templateId: "standard-rti", activeRevision: null }] }));
      }
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
      if (url.includes("/api/provider-catalog/sketch?")) {
        const provider = new URL(`http://barragan.invalid${url}`).searchParams.get("provider") || "linode";
        return Promise.resolve(jsonResponse({ catalog: sketchCatalogFixture(provider) }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-settings")) {
        settingsReads += 1;
        return Promise.resolve(jsonResponse({
          settings: observerSettingsFixture(settingsReads > 1 ? { enabled: false, currentHost: {} } : {
            enabled: true,
            currentHost: { resourceId: "host-123", publicIp: "198.51.100.25", status: "running" }
          })
        }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-cleanup-preview") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({
          preview: {
            engagementId: "eng-ob01",
            engagementName: "OB01",
            confirmationToken: "destroy-inspector-ob01",
            canDestroy: true,
            blockers: [],
            resourceCount: 2,
            scope: { inspectorOnly: true, coreInfrastructure: false },
            hosts: [{
              provider: "linode",
              resourceType: "instance",
              resourceId: "host-123",
              name: "opaque-inspector",
              region: "us-sea",
              publicIp: "198.51.100.25",
              status: "running",
              associatedResources: [{ provider: "linode", resourceType: "firewall", resourceId: "firewall-456", name: "opaque-firewall" }]
            }]
          }
        }));
      }
      if (url.endsWith("/api/engagements/eng-ob01/inspector-cleanup") && init?.method === "POST") {
        return Promise.resolve(jsonResponse({ job: cleanupJob, status: "succeeded" }));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(within(screen.getByRole("navigation", { name: "Engagement workspace sections" })).getByRole("button", { name: "Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Inspector" }));
    const lifecycle = await screen.findByRole("region", { name: "Inspector lifecycle" });
    fireEvent.click(within(lifecycle).getByRole("button", { name: "Review Inspector Cleanup" }));

    await waitFor(() => expect(within(lifecycle).getByText("opaque-inspector")).toBeInTheDocument());
    fireEvent.click(within(lifecycle).getByText("Provider cleanup details (1)"));
    expect(within(lifecycle).getByText("firewall: opaque-firewall")).toBeInTheDocument();
    expect(within(lifecycle).getByRole("button", { name: "Destroy Inspector" })).toBeDisabled();
    fireEvent.change(within(lifecycle).getByLabelText("Inspector cleanup confirmation"), { target: { value: "destroy-inspector-ob01" } });
    fireEvent.click(within(lifecycle).getByRole("button", { name: "Destroy Inspector" }));

    await waitFor(() => expect(within(lifecycle).getByText("Inspector resources were destroyed and scheduling was disabled.")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("not active")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/engagements/eng-ob01/inspector-cleanup",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ confirmation: "destroy-inspector-ob01", requestedBy: "operator" }) })
    );
  });
});

async function openReadyCertificateManager() {
  await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: "Channels" }));
  fireEvent.click(screen.getByRole("button", { name: /^Inbound$/ }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Manage Cert" })).toBeInTheDocument());
  fireEvent.click(screen.getByRole("button", { name: "Manage Cert" }));
  const modal = await screen.findByRole("region", { name: "SSL/TLS Cert Manager" });
  await waitFor(() => expect(within(modal).getByRole("option", { name: /Secure wildcard/ })).toBeInTheDocument());
  return modal;
}

function certificateManagerTestFixture({
  issueStatus,
  pollStatus,
  assetIssueStatus = "succeeded",
  assetPollStatuses = []
}: {
  issueStatus: string;
  pollStatus?: string;
  assetIssueStatus?: string;
  assetPollStatuses?: string[];
}) {
  const channel = {
    channelId: "edge-zy01-us-sea-01-443-to-proxy01-18080",
    domain: "secure.example.com",
    protocol: "HTTPS",
    mode: "https-openresty",
    externalPort: "443",
    edge: "edge-zy01-us-sea-01",
    middle: "middle01-zy01",
    proxy: "proxy01-zy01",
    terminatesOn: "proxy01-zy01",
    service: "Static Web",
    serviceId: "web-static-secure",
    serviceType: "web-static",
    internalPort: "18080",
    purpose: "campaign HTTPS site",
    status: "Validated",
    validation: { status: "Validated", externalIngressVerified: true, detail: "Inbound route validated." }
  };
  const prerequisites = {
    status: "ready",
    ready: true,
    summary: "Ready to request a Let's Encrypt certificate with DNS-01.",
    checkedAt: "2026-06-29T12:00:00+00:00",
    domainAssetId: "domain-secure-example-com",
    challengeType: "dns-01",
    dnsZone: "example.com",
    checks: [
      { id: "https-channel", label: "HTTPS inbound channel", status: "ready", detail: "Ready." },
      { id: "domain-present", label: "Channel domain", status: "ready", detail: "Ready." },
      { id: "domain-assigned", label: "Engagement domain assignment", status: "ready", detail: "Ready." },
      { id: "dns01-provider", label: "DNS-01 provider access", status: "ready", detail: "Ready." }
    ]
  };
  let workspaceCalls = 0;
  let operationsCalls = 0;
  let detailCalls = 0;
  let assetDetailCalls = 0;
  const certificateJob = (status: string) => ({
    ...channelJob("job-certificate-issue", "inbound_channel_certificate_issue"),
    status,
    events: [
      {
        sequence: 1,
        level: "info",
        message: status === "succeeded" ? "selected-proxy certificate issuance succeeded" : "selected-proxy certificate issuance started",
        data: { channelId: channel.channelId }
      }
    ]
  });
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/templates")) {
      return Promise.resolve(jsonResponse({ templates: [] }));
    }
    if (url.endsWith("/api/engagements?scope=all")) {
      return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
    }
    if (url.endsWith("/api/jobs")) {
      return Promise.resolve(jsonResponse({ jobs: [] }));
    }
    if (url.endsWith("/api/dashboard")) {
      return Promise.resolve(jsonResponse({ dashboard: emptyDashboardFixture() }));
    }
    if (url.endsWith("/api/provider-catalog/sketch?provider=linode")) {
      return Promise.resolve(jsonResponse({ catalog: providerCatalog("linode") }));
    }
    if (url.endsWith("/api/provider-catalog/sketch?provider=digitalocean")) {
      return Promise.resolve(jsonResponse({ catalog: providerCatalog("digitalocean") }));
    }
    if (url.endsWith("/api/orchestrator/barragan-testing/pilot-standard-rti/readiness?engagementId=eng-zy01")) {
      return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
    }
    if (url.endsWith("/api/engagements/eng-zy01/sketch-chains")) {
      return Promise.resolve(jsonResponse({ sketchChains: [] }));
    }
    const certificateVersion = {
      id: "certver-secure",
      certificateId: "cert-secure",
      sequence: 1,
      status: "active",
      acmeEnvironment: "production",
      keyGeneration: 1,
      issuer: "CN=R11,O=Let's Encrypt,C=US",
      serialNumber: "abc123",
      fingerprintSha256: "f".repeat(64),
      publicMetadata: { notBefore: "2026-06-29T12:00:00+00:00" },
      paths: {
        liveDir: "/etc/letsencrypt/live/barragan/cert-secure",
        fullchain: "/etc/letsencrypt/live/barragan/cert-secure/current/fullchain.pem",
        cert: "/etc/letsencrypt/live/barragan/cert-secure/current/cert.pem",
        chain: "/etc/letsencrypt/live/barragan/cert-secure/current/chain.pem",
        privkey: "/etc/letsencrypt/live/barragan/cert-secure/current/privkey.pem"
      },
      issuedAt: "2026-06-29T12:00:00+00:00",
      expiresAt: "2026-09-27T19:19:04+00:00",
      revokedAt: "",
      lastJobId: "job-certificate-issue",
      createdAt: "2026-06-29T12:00:00+00:00",
      updatedAt: "2026-06-29T12:00:00+00:00"
    };
    const candidate = {
      id: "cert-secure", name: "Secure wildcard", source: "letsencrypt", targetProxyId: "proxy01-zy01",
      identifiers: ["secure.example.com", "*.example.com"], primaryIdentifier: "secure.example.com", status: "active",
      currentVersionId: "certver-secure", lastJobId: "", notes: "Existing app certificate",
      createdAt: "2026-06-28T12:00:00+00:00", updatedAt: "2026-06-29T12:00:00+00:00",
      currentVersion: certificateVersion, versions: [certificateVersion], bindings: [{ id: "bind-secure", channelId: channel.channelId, hostname: channel.domain, status: "bound" }],
      productionConfirmations: { issue: "issue-token", renew: "renew-token", reissue: "reissue-token", revoke: "revoke-token" }
    };
    const certificateAssetJob = (status = "succeeded") => ({
      id: "job-certificate-asset-issue",
      action: "certificate_asset_issue",
      status,
      requestedBy: "operator",
      targetType: "engagement",
      targetId: "eng-zy01",
      input: { engagementId: "eng-zy01", certificateId: "cert-new" },
      artifactRefs: [],
      createdAt: "2026-06-29T12:00:00+00:00",
      updatedAt: "2026-06-29T12:00:00+00:00",
      finishedAt: status === "succeeded" ? "2026-06-29T12:00:01+00:00" : "",
      events: [{ sequence: 1, level: "info", message: status === "succeeded" ? "certificate asset issuance succeeded" : "certificate asset issuance started", data: { certificateId: "cert-new" } }]
    });
    const certificateBindJob = {
      ...certificateAssetJob(),
      id: "job-certificate-bind",
      action: "certificate_asset_bind",
      targetType: "certificate_binding",
      targetId: "bind-secure",
      events: [{ sequence: 1, level: "info", message: "certificate binding activation succeeded", data: { certificateId: candidate.id } }]
    };
    if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/certificate-binding`) && (!init?.method || init.method === "GET")) {
      workspaceCalls += 1;
      return Promise.resolve(jsonResponse({ channel, certificate: null, binding: null, candidates: [candidate], routeStatus: channel.status, tlsStatus: "unbound" }));
    }
    if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/certificate-binding`) && init?.method === "PATCH") {
      return Promise.resolve(jsonResponse({ channel, certificate: candidate, binding: { id: "bind-secure", certificateId: candidate.id, status: "bound" }, candidates: [candidate], routeStatus: channel.status, tlsStatus: "bound", job: certificateBindJob }));
    }
    if (url.endsWith("/api/engagements/eng-zy01/certificates/cert-secure") && init?.method === "PATCH") {
      return Promise.resolve(jsonResponse({ certificate: { ...candidate, notes: "Updated cert purpose" } }));
    }
    const lifecycleMatch = url.match(/\/api\/engagements\/eng-zy01\/certificates\/cert-secure\/(renew|reissue|revoke)$/);
    if (lifecycleMatch && init?.method === "POST") {
      const action = lifecycleMatch[1];
      return Promise.resolve(jsonResponse({
        certificate: candidate,
        job: { ...certificateAssetJob(), id: `job-certificate-${action}`, action: `certificate_asset_${action}` },
        status: "succeeded"
      }));
    }
    if (url.endsWith("/api/engagements/eng-zy01/certificates") && init?.method === "POST") {
      return Promise.resolve(jsonResponse({ certificate: { ...candidate, id: "cert-new", name: "New wildcard", identifiers: ["new.example.com", "*.new.example.com"], primaryIdentifier: "new.example.com", status: "draft", currentVersionId: "", currentVersion: null, versions: [], bindings: [], notes: "New app cert" } }));
    }
    if (url.endsWith("/api/engagements/eng-zy01/certificates/cert-new/issue") && init?.method === "POST") {
      return Promise.resolve(jsonResponse({ certificate: { ...candidate, id: "cert-new" }, job: certificateAssetJob(assetIssueStatus), status: assetIssueStatus }));
    }
    if (url.endsWith("/api/jobs/job-certificate-asset-issue")) {
      const status = assetPollStatuses[Math.min(assetDetailCalls, assetPollStatuses.length - 1)] ?? assetIssueStatus;
      assetDetailCalls += 1;
      return Promise.resolve(jsonResponse({ job: certificateAssetJob(status) }));
    }
    if (url.endsWith("/api/engagements/eng-zy01/certificates") && (!init?.method || init.method === "GET")) {
      return Promise.resolve(jsonResponse({ certificateManager: { engagement: { id: "eng-zy01", name: "ZY01" }, profile: { engagementId: "eng-zy01", acmeEmail: "operator@example.com", defaultEnvironment: "production", updatedAt: "" }, certificates: [candidate], proxies: [{ id: "proxy01-zy01", label: "proxy01-zy01", status: "deployed" }], sources: ["letsencrypt", "self-signed", "external"], maxIdentifiers: 100 } }));
    }
    if (url.endsWith(`/api/engagements/eng-zy01/inbound-channels/${channel.channelId}/certificate/issue`) && init?.method === "POST") {
      return Promise.resolve(jsonResponse({
        job: certificateJob(issueStatus),
        certificate: { type: "letsencrypt", status: issueStatus === "succeeded" ? "Issued" : "Issuing", domain: channel.domain },
        prerequisites,
        status: issueStatus
      }));
    }
    if (url.endsWith("/api/jobs/job-certificate-issue")) {
      detailCalls += 1;
      return Promise.resolve(jsonResponse({ job: certificateJob(pollStatus ?? issueStatus) }));
    }
    if (url.endsWith("/api/engagements/eng-zy01/operations")) {
      operationsCalls += 1;
      return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([channel]) }));
    }
    return Promise.resolve(jsonResponse({}));
  });
  return {
    channel,
    productionConfirmation: `issue-production-${channel.channelId}-${channel.domain}`,
    fetchMock,
    certificateWorkspaceCalls: () => workspaceCalls,
    operationsCalls: () => operationsCalls,
    jobDetailCalls: () => detailCalls,
    assetJobDetailCalls: () => assetDetailCalls
  };
}

function jsonResponse(body: unknown) {
  return {
    ok: true,
    json: () => Promise.resolve(body)
  };
}

function errorResponse(status: number, body: unknown) {
  return {
    ok: false,
    status,
    json: () => Promise.resolve(body)
  };
}

function emptyDashboardFixture() {
  return {
    generatedAt: "2026-06-17T00:00:00+00:00",
    summary: {
      templates: 0,
      engagements: 1,
      activeEngagements: 1,
      jobRuns: 0,
      activeInfrastructure: 0,
      attention: 0,
      destroyed: 0,
      lastKnown: 0,
      orphanCandidates: 0,
      recentTeardowns: 0,
      recentArchives: 0
    },
    engagementOverview: {
      active: [],
      recentlyEnded: [],
      recentlyArchived: [],
      windowDays: 30
    },
    systemHealth: {
      api: { status: "ok", detail: "Barragan API is responding.", checkedAt: "2026-06-17T00:00:00+00:00" },
      database: { status: "ok", detail: "Database query succeeded.", uriScheme: "sqlite", path: "/tmp/barragan.db", seedStatus: "seeded" },
      disk: { status: "ok", detail: "42% disk used at /tmp.", path: "/tmp", freeBytes: 1, totalBytes: 2, usedPercent: 42 },
      providers: { status: "not checked", detail: "Provider connectivity has not been checked.", checkedAt: null }
    },
    inventory: [],
    orphanCandidates: [],
    reconciliation: {
      status: "local-records",
      detail: "Dashboard inventory is derived from Barragan runtime records."
    }
  };
}

function sketchCatalogFixture(provider: string) {
  const defaults = provider === "digitalocean"
    ? { region: "sfo3", size: "s-1vcpu-1gb" }
    : { region: "us-sea", size: "g6-nanode-1" };
  return {
    provider,
    regions: [{ id: defaults.region, label: defaults.region, available: true }],
    sizes: [
      {
        id: defaults.size,
        label: defaults.size,
        available: true,
        vcpus: null,
        memoryMb: null,
        diskGb: null,
        priceMonthly: null,
        regions: [defaults.region]
      }
    ],
    defaults,
    source: "test",
    cachedAt: "",
    expiresAt: "",
    warnings: [],
    regionPolicy: { allowedRegions: [defaults.region], includeBlocked: false }
  };
}

function observerSettingsFixture(overrides: Record<string, unknown> = {}) {
  return {
    engagementId: "eng-ob01",
    enabled: true,
    provider: "linode",
    region: "us-sea",
    size: "g6-nanode-1",
    mode: "continuous",
    scheduleWeekdays: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
    scheduleTimeUtc: "00:00",
    checkFamilies: ["inbound", "dns", "tls", "forbidden_tcp"],
    forbiddenTcpPorts: ["22", "2222"],
    portScanProfiles: [],
    currentHost: {},
    idleRetentionUntil: "",
    lastScheduledSlot: "",
    lastMutationJobInspected: "",
    configured: false,
    confirmationToken: "inspect-ob01",
    defaults: {
      provider: "linode",
      regions: { linode: "us-sea", digitalocean: "sfo3" },
      sizes: { linode: "g6-nanode-1", digitalocean: "s-1vcpu-1gb" },
      forbiddenTcpPorts: ["22", "2222"],
      mode: "continuous",
      scheduleWeekdays: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
      scheduleTimeUtc: "00:00",
      checkFamilies: ["inbound", "dns", "tls", "forbidden_tcp"]
    },
    ...overrides
  };
}

function orphanCandidateFixture(overrides: Record<string, unknown> = {}) {
  return {
    candidateId: "oci:compute_instance:ocid1.instance.orphan",
    provider: "oci",
    resourceType: "compute_instance",
    resourceId: "ocid1.instance.orphan",
    name: "homebase-or01",
    region: "us-sanjose-1",
    lifecycleState: "RUNNING",
    engagementId: "eng-or01",
    engagementName: "OR01",
    source: "provider_inventory",
    reason: "Provider inventory reports an active resource, but Barragan has no active local deployment state for this engagement.",
    classification: "barragan_orphan",
    actions: ["track", "mark_destroyed", "tear_down"],
    ...overrides
  };
}

function engagementSummary(overrides: Record<string, unknown> = {}) {
  return {
    id: "eng-zy01",
    name: "ZY01",
    status: "draft",
    owner: "example_operator",
    templateId: null,
    activeRevision: null,
    description: "Training exercise",
    documentationUrl: "https://docs.example.invalid/zy01",
    jiraUrl: "https://jira.example.invalid/browse/ZY01",
    lifecycle: {
      state: "not_deployed",
      label: "Not deployed",
      attentionRequired: false,
      terminal: true,
      administrativeStatus: "draft",
      evidence: [],
      evidenceFingerprint: "empty",
      reconciledAt: null
    },
    ...overrides
  };
}

function engagementWorkspace(engagementId: string) {
  return {
    engagementId,
    slug: `${engagementId}-workspace`,
    path: `/tmp/barragan-ui-test/engagements/${engagementId}`,
    status: "prepared",
    profileId: "standard-rti"
  };
}

function domainGroupsFixture(overrides: Record<string, unknown> = {}) {
  return {
    currently_being_used: [
      domainSummaryFixture({
        id: "domain-active",
        domainName: "active.example",
        bucket: "currently_being_used",
        engagement: { id: "eng-zy01", name: "ZY01" },
        purpose: "rti",
        purposeTags: ["rti"],
        notes: "Active RTI route."
      })
    ],
    waiting_to_be_used: [
      domainSummaryFixture({
        id: "domain-waiting",
        domainName: "waiting.example",
        bucket: "waiting_to_be_used"
      })
    ],
    used_in_past_engagements: [
      domainSummaryFixture({
        id: "domain-retired",
        domainName: "retired.example",
        bucket: "used_in_past_engagements",
        healthRisk: {
          status: "cooldown",
          flags: ["cooldown"],
          cooldownUntil: "2026-07-01T00:00:00+00:00",
          assignableOverride: false
        },
        purpose: "email",
        purposeTags: ["email"],
        notes: "Released from a past engagement."
      })
    ],
    ...overrides
  };
}

function domainSummaryFixture(overrides: Record<string, unknown> = {}) {
  return {
    id: "domain-waiting",
    domainName: "waiting.example",
    registrar: "namecheap",
    registration: {
      createdAt: "2024-01-01T00:00:00+00:00",
      expiresAt: "2027-01-01T00:00:00+00:00",
      autoRenew: true
    },
    healthRisk: {
      status: "clear",
      flags: [],
      cooldownUntil: "",
      assignableOverride: false
    },
    providerStatus: "OK",
    notes: "",
    catalogState: "auto",
    lastSyncedAt: "2026-06-13T10:00:00+00:00",
    bucket: "waiting_to_be_used",
    engagement: null,
    purpose: "",
    purposeTags: [],
    dnsSummary: {
      recordCount: 0,
      recordsPreview: [],
      source: "",
      syncJobId: "",
      fetchedAt: ""
    },
    ...overrides
  };
}

function sketchKey(fingerprint: string, retiredKeys: Array<Record<string, string>> = []) {
  return {
    engagementId: "eng-zy01",
    privateKeyName: "zy01-sketch",
    publicKeyName: "zy01-sketch.pub",
    fingerprint,
    retiredKeys,
    createdAt: "2026-06-04T00:00:00+00:00",
    updatedAt: "2026-06-04T00:00:00+00:00"
  };
}

function sketchRotationPlan(currentKey: ReturnType<typeof sketchKey>, blocked: boolean) {
  return {
    engagementId: "eng-zy01",
    status: blocked ? "blocked" : "ready",
    mutation: false,
    currentKey,
    confirmation: "rotate-sketch-key",
    requiresRepair: blocked,
    affectedChains: blocked
      ? [
          {
            chainId: "proxy01-sea-01",
            assignedProxy: "proxy01",
            status: "deployed",
            requiredAction: "reprovision_or_opsec_safe_repair",
            nodes: [{ hostname: "middle-zy01-proxy01-sea-01", role: "middle", provider: "linode", publicIp: "203.0.113.10" }]
          }
        ]
      : [],
    steps: blocked
      ? [
          {
            id: "inspect-affected-chains",
            status: "blocked",
            detail: "Existing sketch chains require reprovisioning or an OPSEC-safe repair path before key rotation."
          }
        ]
      : [
          {
            id: "generate-new-keypair",
            status: "ready",
            detail: "Generate a new encrypted engagement-scoped keypair."
          }
        ],
    opsecBoundary: {
      directSketchAccess: false,
      middleAccess: "proxy jump only",
      edgeAccess: "proxy to middle jump only"
    }
  };
}

function sketchRemovalPlan(currentKey: ReturnType<typeof sketchKey>, blocked: boolean) {
  return {
    engagementId: "eng-zy01",
    status: blocked ? "blocked" : "ready",
    mutation: false,
    currentKey,
    confirmation: "remove-sketch-key",
    requiresTeardown: blocked,
    blockers: blocked
      ? [
          {
            kind: "sketch_chain",
            chainId: "proxy01-sea-01",
            assignedProxy: "proxy01",
            status: "deployed",
            requiredAction: "tear_down_sketch_chain_first"
          }
        ]
      : [],
    steps: blocked
      ? [
          {
            id: "verify-teardown",
            status: "blocked",
            detail: "Tear down recorded core and sketch infrastructure before removing encrypted sketch key material."
          }
        ]
      : [
          {
            id: "remove-encrypted-key",
            status: "ready",
            detail: "Delete Barragan's encrypted engagement sketch key material."
          }
        ],
    opsecBoundary: {
      directSketchAccess: false,
      middleAccess: "proxy jump only",
      edgeAccess: "proxy to middle jump only"
    }
  };
}

function standardInput() {
  return {
    engagementName: "ZY01",
    proxyCount: 2,
    elkEnabled: false,
    sketchChains: [{
      id: "chain-1",
      assignedProxy: "proxy01",
      middleProvider: "linode",
      edgeProvider: "digitalocean",
      middleRegion: "us-sea",
      edgeRegion: "sfo3",
      middleSize: "g6-nanode-1",
      edgeSize: "s-1vcpu-1gb"
    }],
    egressProfiles: [{ name: "default-sketch-egress", sketchChainId: "chain-1", listenerPort: 3333 }],
    ingressRoutes: [{ name: "default-ingress", sketchChainId: "chain-1", domain: "example.invalid" }],
    reverseChannels: []
  };
}

function standardComputeProfileFixture() {
  return {
    id: "standard-rti",
    name: "Standard RTI",
    fingerprint: "a".repeat(64),
    bootVolumeSizeGiB: 512,
    roles: [
      { role: "homebase", label: "Homebase", nodeCount: 1, shape: "BM.Standard3.64", ocpus: 64, memoryGiB: 1024 },
      { role: "proxy", label: "Proxy", nodeCount: 2, shape: "VM.Standard.E4.Flex", ocpus: 2, memoryGiB: 32 },
      { role: "elk", label: "ELK", nodeCount: 0, shape: "VM.Standard.E4.Flex", ocpus: 2, memoryGiB: 32 }
    ]
  };
}

function corePlanReviewFixture(overrides: Record<string, unknown> = {}) {
  const cidrs = (overrides.sshSourceCidrs as string[] | undefined) ?? ["159.54.185.107/32", "160.34.86.0/23"];
  return {
    id: "plan-current",
    engagementId: "eng-zy01",
    revisionId: "rev-plan-current",
    status: "ready",
    stage: "ready",
    counts: { add: 1, update: 0, replace: 0, remove: 0, read: 0, output: 0 },
    resourceChanges: [{ action: "add", address: "oci_core_instance.homebase", type: "OCI instance", provider: "oci", displayName: "Homebase", group: "Compute", region: "us-sanjose-1" }],
    target: { name: "barragan-testing", region: "us-sanjose-1" },
    reviewedConfiguration: {
      templateId: "standard-rti",
      templateName: "Standard RTI",
      core: { homebases: 1, proxies: 2, elkEnabled: false },
      target: { name: "barragan-testing", region: "us-sanjose-1" },
      sshSourceCidrs: cidrs
    },
    postCoreScope: {
      chainCount: 2,
      middleCount: 2,
      edgeCount: 4,
      providers: ["digitalocean", "linode"],
      chains: ["proxy01", "proxy02"].map((proxy) => ({
        id: `${proxy}-chain-1`,
        assignedProxy: proxy,
        middle: { provider: "linode", region: "us-sea" },
        edges: [1, 2].map((index) => ({ id: `edge-${String(index).padStart(2, "0")}`, provider: "digitalocean", region: "sfo3" }))
      }))
    },
    preparedAt: "2026-08-05T14:00:00Z",
    ageWarningAt: "2099-08-05T15:00:00Z",
    sshSourceCidrs: cidrs,
    inputFingerprint: "opaque-plan-fingerprint",
    computeProfile: standardComputeProfileFixture(),
    sanitizedTextKind: "summary",
    sanitizedText: "Plan summary: add=1 update=0 replace=0 remove=0 output=0",
    terraformFiles: [],
    error: null,
    ...overrides
  };
}

function pilotRunJob(engagementId: string | null = null) {
  const engagementName = engagementNameForId(engagementId);
  return {
    id: "job-pilot-001",
    action: "pilot_standard_rti_guarded_execute",
    status: "succeeded",
    targetType: "oci_compartment",
    targetId: "ocid1.compartment.oc1..example7dd502b6e3a0a13e825f0910",
    requestedBy: "operator",
    input: {
      engagementId,
      engagementName,
      resourceNames: {
        homebase: `homebase-${engagementName}`,
        proxy01: `proxy01-${engagementName}`,
        vcn: `${engagementName}-vcn`
      },
      workspace: "barragan-pilot-standard-rti",
      workspaceDir: "/tmp/barragan-ui-test",
      deploymentMode: "hold_for_review",
      sshSourceCidrs: ["159.54.185.107/32", "160.34.86.0/23"]
    },
    artifactRefs: ["workspace:/tmp/barragan-ui-test"],
    events: [
      { sequence: 1, level: "info", message: "pilot Standard RTI run queued", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 2, level: "info", message: "pilot Standard RTI run started", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 3, level: "info", message: "readiness and guardrails accepted", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 4, level: "info", message: "OCI read preflight completed", data: { ok: true, mutationStatus: "deployed" } },
      { sequence: 5, level: "info", message: "Terraform init completed", data: { status: "succeeded" } },
      { sequence: 6, level: "info", message: "Terraform apply completed", data: { status: "succeeded" } },
      { sequence: 7, level: "info", message: "Terraform output completed", data: { status: "succeeded" } },
      { sequence: 8, level: "info", message: "SSH readiness validation completed", data: { status: "succeeded" } },
      { sequence: 9, level: "info", message: "Ansible ping validation completed", data: { status: "succeeded" } },
      { sequence: 10, level: "info", message: "Ansible bootstrap validation completed", data: { status: "succeeded" } },
      {
        sequence: 11,
        level: "info",
        message: "operator inspection ready",
        data: {
          status: "deployed",
          workspace: "barragan-pilot-standard-rti",
          workspaceDir: "/tmp/barragan-ui-test",
          connectionDetails: pilotConnectionDetails(engagementName)
        }
      },
      {
        sequence: 12,
        level: "info",
        message: "pilot Standard RTI run finished",
        data: {
          ok: true,
          workspace: "barragan-pilot-standard-rti",
          workspaceDir: "/tmp/barragan-ui-test",
          mutationStatus: "deployed",
          ansibleStatus: "validated",
          finalCleanupStatus: "pending_operator_teardown",
          deploymentMode: "hold_for_review",
          connectionDetails: pilotConnectionDetails(engagementName)
        }
      }
    ]
  };
}

function pilotConnectionDetails(engagementName = "pilot") {
  return [
    {
      role: "homebase",
      displayName: `homebase-${engagementName}`,
      sshAlias: `homebase-${engagementName}`,
      publicIp: "146.235.219.8",
      privateIp: "192.168.0.10",
      sshUser: "ubuntu",
      sshCommand: `ssh homebase-${engagementName}`,
      services: ["SSH", "RTI base layout", "proxy config banks", "dropbox NFS export"]
    },
    {
      role: "proxy",
      displayName: `proxy01-${engagementName}`,
      sshAlias: `proxy01-${engagementName}`,
      publicIp: "170.9.62.26",
      privateIp: "192.168.2.11",
      sshUser: "ubuntu",
      sshCommand: `ssh proxy01-${engagementName}`,
      services: ["SSH", "RTI base layout", "dropbox NFS mount"]
    }
  ];
}

function pilotRunningJob(engagementId: string | null = null) {
  return {
    ...pilotRunJob(engagementId),
    status: "running",
    artifactRefs: [],
    events: [
      { sequence: 1, level: "info", message: "pilot Standard RTI run queued", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 2, level: "info", message: "pilot Standard RTI run started", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 3, level: "info", message: "readiness and guardrails accepted", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 4, level: "info", message: "pilot Standard RTI executor running", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } }
    ]
  };
}

function pilotTornDownJob(engagementId: string | null = null) {
  return {
    ...pilotRunJob(engagementId),
    action: "engagement_comprehensive_teardown",
    events: [
      ...pilotRunJob(engagementId).events,
      { sequence: 19, level: "info", message: "engagement teardown queued", data: { snapshotId: "snapshot-zy01" } },
      { sequence: 20, level: "info", message: "engagement sketch cleanup started", data: { phase: "outbound_and_sketch_cleanup" } },
      { sequence: 21, level: "info", message: "sketch chain cleanup verified", data: { chainId: "proxy01-sea-01" } },
      { sequence: 22, level: "info", message: "core and Inspector cleanup started", data: { phase: "core_and_inspector_cleanup" } },
      { sequence: 13, level: "info", message: "operator teardown requested", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 14, level: "info", message: "Terraform destroy completed", data: { step: "terraform_destroy", status: "succeeded", returncode: 0, cwd: "/tmp/barragan-ui-test" } },
      { sequence: 15, level: "info", message: "cleanup verification completed", data: { status: "verified_clean", ok: true, remainingCount: 0 } },
      { sequence: 16, level: "info", message: "Inspector teardown verification completed", data: { status: "verified_absent", ok: true, targetCount: 2 } },
      { sequence: 17, level: "info", message: "Inspector cleanup completed", data: { status: "destroyed", ok: true, cleanupVerified: true } },
      {
        sequence: 23,
        level: "info",
        message: "pilot Standard RTI teardown finished",
        data: {
          ok: true,
          workspace: "barragan-pilot-standard-rti",
          workspaceDir: "/tmp/barragan-ui-test",
          mutationStatus: "destroyed",
          ansibleStatus: "not_started",
          finalCleanupStatus: "verified_clean",
          inspectorTeardownVerification: { status: "verified_absent", ok: true, targetCount: 2 },
          inspectorCleanup: { status: "destroyed", ok: true, cleanupVerified: true },
          deploymentMode: "destroy_after_validation"
        }
      },
      { sequence: 24, level: "info", message: "engagement resource cleanup gates passed", data: { finalCleanupStatus: "verified_clean" } },
      { sequence: 25, level: "info", message: "engagement lifecycle reconciled", data: { state: "destroyed", finalCleanupStatus: "verified_clean" } }
    ]
  };
}

function pilotCleanupNotVerifiedJob(engagementId: string | null = null) {
  return {
    ...pilotRunJob(engagementId),
    status: "failed",
    events: [
      ...pilotRunJob(engagementId).events,
      { sequence: 13, level: "info", message: "operator teardown requested", data: { workspace: "barragan-pilot-standard-rti", workspaceDir: "/tmp/barragan-ui-test" } },
      { sequence: 14, level: "error", message: "Terraform destroy completed", data: { step: "terraform_destroy", status: "failed", returncode: 1, cwd: "/tmp/barragan-ui-test" } },
      { sequence: 15, level: "error", message: "cleanup verification completed", data: { status: "cleanup_not_verified", ok: null, remainingCount: null } },
      {
        sequence: 16,
        level: "error",
        message: "pilot Standard RTI teardown finished",
        data: {
          ok: false,
          workspace: "barragan-pilot-standard-rti",
          workspaceDir: "/tmp/barragan-ui-test",
          mutationStatus: "destroy_failed",
          ansibleStatus: "not_started",
          finalCleanupStatus: "cleanup_not_verified",
          deploymentMode: "destroy_after_validation"
        }
      }
    ]
  };
}

function comprehensiveRecoveryJob(id: string, engagementId = "eng-zy01") {
  const base = pilotCleanupNotVerifiedJob(engagementId);
  const coreJobId = "job-pilot-001";
  return {
    ...base,
    id,
    action: "engagement_comprehensive_teardown",
    targetType: "engagement",
    targetId: engagementId,
    input: {
      ...base.input,
      engagementId,
      coreJobId,
      scopeSnapshot: {
        engagementId,
        engagementName: "ZY01",
        coreJobId,
        snapshotId: "snapshot-immutable-1",
        confirmationPhrase: "teardown-ZY01",
        chains: [],
        ownedProviderRecordIds: [],
        excludedUnmanagedProviderRecords: [],
        core: { jobId: coreJobId, workspace: "/tmp/core", proxyCount: 2 },
        publicVerificationTargets: [],
        inspector: { tracked: false, ownedProviderRecordIds: [], recordOwners: {}, verificationTargetCount: 0 }
      }
    }
  };
}

function linodeSketchJob(engagementId: string | null = null) {
  return {
    id: "job-sketch-001",
    action: "linode_sketch_guarded_execute",
    status: "succeeded",
    targetType: "sketch_chain",
    targetId: "proxy01-chain-1",
    requestedBy: "operator",
    input: {
      engagementId,
      coreJobId: "job-pilot-001",
      chainId: "proxy01-chain-1",
      assignedProxy: "proxy01",
      middleRegion: "us-sea",
      middleSize: "g6-nanode-1",
      edgeRegion: "us-sea",
      edgeSize: "g6-nanode-1"
    },
    artifactRefs: ["workspace:/tmp/barragan-linode-sketch-ui-test"],
    events: [
      { sequence: 1, level: "info", message: "Linode sketch run queued", data: { workspaceDir: "/tmp/barragan-linode-sketch-ui-test" } },
      { sequence: 2, level: "info", message: "Linode sketch Terraform init completed", data: { status: "succeeded" } },
      { sequence: 3, level: "info", message: "Linode sketch Terraform apply completed", data: { status: "succeeded" } },
      { sequence: 4, level: "info", message: "Linode sketch run finished", data: { finalCleanupStatus: "pending_operator_teardown" } }
    ]
  };
}

function sketchPowerJob(action: "sketch_chain_stop" | "sketch_chain_start") {
  const operation = action === "sketch_chain_stop" ? "stop" : "start";
  const status = operation === "stop" ? "stopped" : "deployed";
  return {
    id: `job-${action}`,
    action,
    status: "succeeded",
    targetType: "engagement",
    targetId: "eng-zy01",
    requestedBy: "operator",
    input: {
      engagementId: "eng-zy01",
      chainId: "proxy01-sea-01",
      provider: "linode",
      credentialAlias: "linode-barragan",
      mutation: true
    },
    artifactRefs: [],
    events: [
      {
        sequence: 1,
        level: "info",
        message: `sketch chain ${operation} queued`,
        data: { chainId: "proxy01-sea-01", provider: "linode", mutation: true }
      },
      {
        sequence: 2,
        level: "info",
        message: `sketch chain ${operation} completed`,
        data: {
          chainId: "proxy01-sea-01",
          provider: "linode",
          status,
          opsecBoundary: { providerApiOnly: true, directSketchAccessFromAppHost: false }
        }
      }
    ]
  };
}

function sketchTeardownJob(status: "running" | "succeeded") {
  return {
    id: "job-sketch-teardown",
    action: "linode_sketch_teardown",
    status,
    targetType: "engagement",
    targetId: "eng-zy01",
    requestedBy: "operator",
    input: { engagementId: "eng-zy01", chainId: "proxy01-sea-01" },
    artifactRefs: [],
    events: status === "running"
      ? [{ sequence: 1, level: "info", message: "Linode sketch teardown started", data: { phase: "destroy" } }]
      : [
          { sequence: 1, level: "info", message: "Linode sketch teardown started", data: { phase: "destroy" } },
          { sequence: 2, level: "info", message: "terraform destroy completed", data: { phase: "destroy" } },
          { sequence: 3, level: "info", message: "terraform cleanup verified", data: { phase: "cleanup", cleanupVerified: true } }
        ]
  };
}

function sketchChainRecord(chainId = "proxy01-sea-01") {
  return {
    chainId,
    engagementId: "eng-zy01",
    assignedProxy: "proxy01",
    middleProvider: "linode",
    middleRegion: "us-sea",
    middleSize: "g6-nanode-1",
    edgeProvider: "linode",
    edgeRegion: "us-sea",
    edgeSize: "g6-nanode-1",
    edgeCount: 1,
    edges: [{ id: "edge-01", provider: "linode", region: "us-sea", size: "g6-nanode-1" }],
    status: "pending",
    burned: false,
    burnedNote: "",
    deployJobId: "",
    teardownJobId: "",
    terraformWorkingDirectory: "",
    nodes: [],
    createdAt: "2026-06-04T12:00:00+00:00",
    updatedAt: "2026-06-04T12:00:00+00:00"
  };
}

function sketchChainInput(
  id: string,
  assignedProxy: string,
  middleProvider: string,
  middleRegion: string,
  edgeProvider: string,
  edgeRegion: string
) {
  const middleSize = middleProvider === "linode" ? "g6-nanode-1" : "s-1vcpu-1gb";
  const edgeSize = edgeProvider === "linode" ? "g6-nanode-1" : "s-1vcpu-1gb";
  return {
    id,
    assignedProxy,
    middleProvider,
    middleRegion,
    middleSize,
    edgeProvider,
    edgeRegion,
    edgeSize,
    edgeCount: 1,
    edges: [{ id: "edge-01", provider: edgeProvider, region: edgeRegion, size: edgeSize }]
  };
}

function compiledSketchRevision(id: string, sketchChains: ReturnType<typeof sketchChainInput>[]) {
  return {
    id,
    engagementId: "eng-zy01",
    revisionNumber: 1,
    status: "compiled",
    templateId: "standard-rti",
    inputParameters: { ...standardInput(), sketchChains },
    resolvedTopology: {},
    runIntent: [],
    validationGates: validationGates()
  };
}

function sketchChainRecordFromBody(chainId: string, body: Record<string, unknown>) {
  return {
    ...sketchChainRecord(chainId),
    assignedProxy: String(body.assignedProxy ?? ""),
    middleProvider: String(body.middleProvider ?? ""),
    middleRegion: String(body.middleRegion ?? ""),
    middleSize: String(body.middleSize ?? ""),
    edgeProvider: String(body.edgeProvider ?? ""),
    edgeRegion: String(body.edgeRegion ?? ""),
    edgeSize: String(body.edgeSize ?? ""),
    edgeCount: Number(body.edgeCount ?? 1),
    edges: Array.isArray(body.edges) ? body.edges : [{ id: "edge-01", provider: String(body.edgeProvider ?? ""), region: String(body.edgeRegion ?? ""), size: String(body.edgeSize ?? "") }]
  };
}

function sketchDeployJob(id: string, action: string, chainId: string, assignedProxy: string) {
  return {
    id,
    action,
    status: "running",
    targetType: "engagement",
    targetId: "eng-zy01",
    requestedBy: "operator",
    input: {
      engagementId: "eng-zy01",
      coreJobId: "job-pilot-001",
      chainId,
      assignedProxy
    },
    artifactRefs: [],
    events: [{ sequence: 1, level: "info", message: "sketch deployment queued", data: { chainId, assignedProxy } }]
  };
}

function failedBootstrapJob(id: string, chainId: string) {
  const job = sketchDeployJob(id, "linode_sketch_deploy", chainId, "proxy01");
  return {
    ...job,
    status: "failed",
    events: [
      ...job.events,
      {
        sequence: job.events.length + 1,
        level: "error",
        message: "sketch bootstrap failed; provider infrastructure retained for retry",
        data: { bootstrap: "failed", error: "readiness failed" }
      }
    ]
  };
}

function validationGates() {
  return [
    {
      id: "core-topology",
      label: "Core topology",
      status: "passed",
      severity: "info",
      message: "Standard OCI homebase and two-proxy core topology is resolved."
    },
    {
      id: "sketch-chain-topology",
      label: "Sketch chain topology",
      status: "passed",
      severity: "info",
      message: "Every sketch chain has resolved middle and edge node groups."
    },
    {
      id: "route-chain-references",
      label: "Route chain references",
      status: "passed",
      severity: "info",
      message: "Egress, ingress, and reverse-channel routes all reference declared sketch chains."
    },
    {
      id: "sketch-management-opsec",
      label: "Sketch management opsec",
      status: "passed",
      severity: "info",
      message: "Sketch management paths route through Barragan, homebase, and the assigned proxy."
    },
    {
      id: "plan-only-intent",
      label: "Plan-only intent",
      status: "passed",
      severity: "info",
      message: "Run intent is dry-run only and does not request live mutation."
    }
  ];
}

function providerCatalog(provider: "linode" | "digitalocean") {
  if (provider === "linode") {
    return {
      provider: "linode",
      regions: [
        { id: "us-sea", label: "Seattle", available: true },
        { id: "us-ord", label: "Chicago", available: true },
        { id: "us-iad", label: "Washington, DC", available: true }
      ],
      sizes: [
        { id: "g6-nanode-1", label: "Nanode 1 GB", vcpus: 1, memoryMb: 1024, diskGb: 25, priceMonthly: 5, available: true, regions: [] },
        { id: "g6-standard-1", label: "Linode 2 GB", vcpus: 1, memoryMb: 2048, diskGb: 50, priceMonthly: 12, available: true, regions: [] }
      ],
      defaults: { region: "us-sea", size: "g6-nanode-1" },
      source: "live",
      cachedAt: "2026-06-04T00:00:00+00:00",
      expiresAt: "2026-06-04T12:00:00+00:00",
      warnings: [],
      regionPolicy: {
        allowedRegions: ["us-sea", "us-ord", "us-iad"],
        includeBlocked: false
      }
    };
  }
  return {
    provider: "digitalocean",
    regions: [{ id: "sfo3", label: "San Francisco 3", available: true }],
    sizes: [
      { id: "s-1vcpu-1gb", label: "Basic 1 vCPU / 1 GB", vcpus: 1, memoryMb: 1024, diskGb: 25, priceMonthly: 6, available: true, regions: ["sfo3"] }
    ],
    defaults: { region: "sfo3", size: "s-1vcpu-1gb" },
    source: "live",
    cachedAt: "2026-06-04T00:00:00+00:00",
    expiresAt: "2026-06-04T12:00:00+00:00",
    warnings: [],
    regionPolicy: {
      allowedRegions: ["sfo3"],
      includeBlocked: false
    }
  };
}

function engagementNameForId(engagementId: string | null): string {
  if (engagementId === "eng-created") {
    return "zy01";
  }
  if (engagementId === "eng-zy01") {
    return "zy01";
  }
  if (engagementId === "eng-old") {
    return "old";
  }
  return "pilot";
}

function pilotReadiness() {
  const target = {
    name: "barragan-testing",
    compartmentId: "ocid1.compartment.oc1..example7dd502b6e3a0a13e825f0910",
    parentCompartmentId: "ocid1.compartment.oc1..parent",
    region: "us-sanjose-1",
    auth: "instance_principal",
    mutation: false,
    classification: "testing" as const
  };
  return {
    target,
    availableTargets: [
      target,
      ...[1, 2, 3, 4].map((number) => ({
        ...target,
        name: `RedTeam-${number}`,
        compartmentId: `ocid1.compartment.oc1..redteam${number}`,
        classification: "production" as const
      }))
    ],
    workspace: "barragan-pilot-standard-rti",
    mutationScope: "disposable two-node Standard RTI pilot with base host layout configuration",
    expectedInstanceDisplayNames: ["homebase-zy01", "proxy01-zy01"],
    topology: {
      template: "Standard RTI",
      engagementName: "zy01",
      vcnCidr: "192.168.0.0/16",
      subnets: [
        { role: "homebase", cidr: "192.168.0.0/24", privateIp: "192.168.0.10" },
        { role: "proxy", cidr: "192.168.2.0/24", privateIp: "192.168.2.11" }
      ],
      nodes: [
        { role: "homebase", displayName: "homebase-zy01", privateIp: "192.168.0.10" },
        { role: "proxy", displayName: "proxy01-zy01", privateIp: "192.168.2.11" }
      ],
      deferred: ["real routes", "DNS", "certificates", "reverse channels"]
    },
    confirmationToken: "mutate-barragan-testing",
    deploymentModes: {
      default: "hold_for_review",
      supported: ["hold_for_review", "destroy_after_validation"]
    },
    cleanupAcknowledgement: {
      field: "confirmDestroyCleanup",
      required: false,
      label: "Immediate destroy is available for automated smoke tests. Operator deploys hold for inspection until Tear Down is requested."
    },
    commands: {
      planned: [
        ["terraform", "init", "-input=false"],
        ["terraform", "apply", "-input=false", "-auto-approve"],
        ["terraform", "output", "-json"],
        ["ansible", "validation_target", "-m", "ansible.builtin.wait_for_connection"],
        ["ansible", "validation_target", "-m", "ping"],
        ["ansible-playbook", "ansible/bootstrap_validate.yml"],
        ["terraform", "destroy", "-input=false", "-auto-approve"]
      ],
      cleanupVerification: [["oci", "compute", "instance", "list"]]
    },
    commandResolution: {
      oci: { binaryName: "oci", command: "/usr/bin/oci", source: "path", overrideVariables: ["OCI_CLI_PATH"], ok: true, error: null },
      terraform: { binaryName: "terraform", command: "/usr/bin/terraform", source: "path", overrideVariables: ["TERRAFORM_BIN"], ok: true, error: null },
      ansible: { binaryName: "ansible", command: "/usr/bin/ansible", source: "path", overrideVariables: ["ANSIBLE_BIN", "ANSIBLE_PATH"], ok: true, error: null },
      ansiblePlaybook: { binaryName: "ansible-playbook", command: "/usr/bin/ansible-playbook", source: "path", overrideVariables: ["ANSIBLE_PLAYBOOK_BIN", "ANSIBLE_PLAYBOOK_PATH"], ok: true, error: null }
    },
    sshKeyConfiguration: {
      publicKeyEnv: "BARRAGAN_VALIDATION_SSH_PUBLIC_KEY",
      privateKeyEnv: "BARRAGAN_VALIDATION_SSH_PRIVATE_KEY",
      sourceCidrEnv: "BARRAGAN_VALIDATION_SSH_SOURCE_CIDR",
      sourceCidrsEnv: "BARRAGAN_VALIDATION_SSH_SOURCE_CIDRS",
      publicKeyConfigured: true,
      privateKeyConfigured: true,
      sourceCidrConfigured: true,
      sourceCidrsConfigured: true
    },
    sshIngress: {
      sourceCidrEnv: "BARRAGAN_VALIDATION_SSH_SOURCE_CIDR",
      sourceCidrsEnv: "BARRAGAN_VALIDATION_SSH_SOURCE_CIDRS",
      sourceCidrConfigured: true,
      sourceCidrsConfigured: true,
      defaultSourceCidrs: [
        "159.54.185.107/32",
        "160.34.86.0/23",
        "160.34.88.0/21",
        "160.34.104.0/21",
        "160.34.112.0/20"
      ],
      allowsPublicInternet: false,
      publicInternetCidr: "0.0.0.0/0",
      requirement: "SSH ingress must use trusted source CIDRs."
    },
    sshReadiness: {
      bounded: true,
      module: "ansible.builtin.wait_for_connection",
      timeoutSeconds: 180,
      sleepSeconds: 5,
      connectTimeoutSeconds: 10,
      knownHostsPath: "ssh/known_hosts",
      hostKeyPolicy: "accept-new in the disposable workspace only"
    },
    guardrails: {
      allowedCompartment: "barragan-testing",
      allowedCompartmentId: "ocid1.compartment.oc1..example7dd502b6e3a0a13e825f0910",
      allowedRegion: "us-sanjose-1",
      noTouchCompartments: ["RedTeam", "RedTeam-1"],
      mutationBoundary: "disposable two-node Standard RTI pilot with base host layout configuration",
      harmlessAnsibleActions: [
        "SSH readiness",
        "ansible.builtin.ping",
        "gather_facts/setup",
        "configure /dropbox NFS export and proxy mounts",
        "create /opt/proxy01 and /opt/proxy02 on homebase",
        "create proxy runtime directory"
      ],
      disallowedResourceFamilies: ["Vault/KMS/secrets"]
    }
  };
}

function operationsWithDeployedSketch(inboundChannels: Array<Record<string, unknown>>) {
  return {
    ...operationsOverview(""),
    coreInfrastructure: [
      ...operationsOverview("").coreInfrastructure,
      {
        hostId: "proxy01",
        logicalName: "proxy01",
        expectedHostname: "proxy01-zy01",
        hostname: "proxy01-zy01",
        role: "proxy",
        publicIp: "203.0.113.11",
        privateIp: "192.168.2.11",
        region: "us-sanjose-1",
        compartment: "barragan-testing",
        services: ["SSH", "OpenResty"],
        health: {
          status: "healthy",
          source: "deployment validation",
          lastCheckedAt: "2026-06-03T12:05:00+00:00",
          stale: false,
          detail: "Last deployment validation succeeded."
        }
      },
      {
        hostId: "proxy02",
        logicalName: "proxy02",
        expectedHostname: "proxy02-zy01",
        hostname: "proxy02-zy01",
        role: "proxy",
        publicIp: "203.0.113.12",
        privateIp: "192.168.3.11",
        region: "us-sanjose-1",
        compartment: "barragan-testing",
        services: ["SSH", "OpenResty"],
        health: {
          status: "healthy",
          source: "deployment validation",
          lastCheckedAt: "2026-06-03T12:05:00+00:00",
          stale: false,
          detail: "Last deployment validation succeeded."
        }
      }
    ],
    sketchInfrastructure: [
      {
        chainId: "chain-1",
        componentId: "middle-chain-1",
        hostname: "middle01-zy01",
        provider: "linode",
        role: "middle",
        publicIp: "198.51.100.20",
        region: "us-sea",
        proxy: "proxy01",
        assignedProxyId: "proxy01",
        status: "deployed",
        burned: false,
        burnedNote: ""
      },
      {
        chainId: "chain-1",
        componentId: "edge-chain-1",
        hostname: "edge-zy01-us-sea-01",
        provider: "linode",
        role: "edge",
        publicIp: "198.51.100.30",
        region: "us-sea",
        proxy: "proxy01",
        assignedProxyId: "proxy01",
        status: "deployed",
        burned: false,
        burnedNote: ""
      },
      {
        chainId: "chain-2",
        componentId: "middle-chain-2",
        hostname: "middle02-zy01",
        provider: "digitalocean",
        role: "middle",
        publicIp: "198.51.100.40",
        region: "nyc3",
        proxy: "proxy02",
        assignedProxyId: "proxy02",
        status: "deployed",
        burned: false,
        burnedNote: ""
      },
      {
        chainId: "chain-2",
        componentId: "edge-chain-2",
        hostname: "edge-zy01-us-ash-02",
        provider: "digitalocean",
        role: "edge",
        publicIp: "198.51.100.50",
        region: "nyc3",
        proxy: "proxy02",
        assignedProxyId: "proxy02",
        status: "deployed",
        burned: false,
        burnedNote: ""
      }
    ],
    outboundChannels: [],
    inboundChannels
  };
}

function operationsOverview(housekeepingItems: string) {
  return {
    engagementId: "eng-zy01",
    housekeepingItems,
    activeJob: {
      id: "job-pilot-001",
      action: "pilot_standard_rti_guarded_execute",
      status: "succeeded",
      createdAt: "2026-06-03T12:00:00+00:00",
      finishedAt: "2026-06-03T12:05:00+00:00"
    },
    healthSummary: {
      status: "healthy",
      source: "deployment validation",
      lastCheckedAt: "2026-06-03T12:05:00+00:00",
      stale: false,
      detail: "Last-known deployment validation status.",
      hostCount: 1,
      activeHostCount: 1
    },
    coreInfrastructure: [
      {
        hostId: "homebase",
        logicalName: "homebase",
        expectedHostname: "homebase-zy01",
        hostname: "homebase-zy01",
        role: "homebase",
        status: "active",
        lifecycleState: "active",
        lastKnown: false,
        publicIp: "146.235.219.8",
        privateIp: "192.168.0.10",
        region: "us-sanjose-1",
        compartment: "barragan-testing",
        services: ["SSH", "Mythic"],
        health: {
          status: "healthy",
          source: "deployment validation",
          lastCheckedAt: "2026-06-03T12:05:00+00:00",
          stale: false,
          detail: "Last deployment validation succeeded."
        }
      }
    ],
    sketchInfrastructure: [
      {
        chainId: "chain-1",
        hostname: "middle-zy01",
        provider: "linode",
        role: "middle",
        publicIp: "198.51.100.20",
        region: "us-ord",
        proxy: "proxy01-zy01",
        status: "healthy"
      },
      {
        chainId: "chain-1",
        hostname: "edge-zy01",
        provider: "digitalocean",
        role: "edge",
        publicIp: "198.51.100.30",
        region: "sfo3",
        proxy: "proxy01-zy01",
        status: "healthy"
      }
    ],
    providerFindings: [],
    servicePlacements: [],
    outboundChannels: [
      {
        chainId: "chain-1",
        proxy: "proxy01-zy01",
        middle: "middle-zy01",
        edge: "edge-zy01",
        port: "3333",
        region: "N/A",
        provider: "digitalocean",
        domain: "example.invalid",
        purpose: "operator route",
        status: "Pending Core Apply",
        profileName: "proxy01-egress",
        publicationPath: "/opt/proxy01/proxychains.conf",
        validation: {
          origin: "homebase",
          command: ["curl", "-sS", "--connect-timeout", "10", "-x", "socks5h://proxy01:3333", "https://ipv4.icanhazip.com"],
          shellDisplay: "curl -sS --connect-timeout 10 -x socks5h://proxy01:3333 https://ipv4.icanhazip.com",
          expectedPublicIp: "203.0.113.30",
          status: "Pending Validation",
          checkedAt: "",
          lastCheckedAt: "",
          detail: "Validation has not run yet."
        },
        artifactTargets: {
          inventory: "ansible/inventory.ini",
          playbook: "ansible/apply_outbound_channel.yml",
          manifest: "manifest.json"
        }
      }
    ],
    inboundChannels: [
      {
        channelId: "default-ingress",
        domain: "example.invalid",
        protocol: "TCP",
        externalPort: "443",
        edge: "Not Deployed",
        middle: "middle-zy01",
        proxy: "proxy01",
        terminatesOn: "proxy01-zy01",
        service: "SSH Backflips",
        internalPort: "8001",
        purpose: "operator access",
        status: "Not Ready"
      }
    ],
    sshConfig: {
      stanza: "Host homebase-zy01\n    HostName 146.235.219.8\n    User ubuntu",
      downloadName: "zy01-ssh-config"
    }
  };
}

function emptyOperationsOverview(housekeepingItems: string) {
  const overview = operationsOverview(housekeepingItems);
  return {
    ...overview,
    lifecycle: { state: "not_deployed", label: "Not deployed", attentionRequired: false, terminal: false },
    activeJob: null,
    coreJob: null,
    teardownJob: null,
    healthSummary: {
      ...overview.healthSummary,
      status: "unknown",
      detail: "No active infrastructure recorded.",
      hostCount: 0,
      activeHostCount: 0
    },
    coreInfrastructure: [],
    sketchInfrastructure: [],
    outboundChannels: [],
    inboundChannels: [],
    sshConfig: {
      stanza: "",
      downloadName: "engagement-ssh-config"
    }
  };
}

function channelJob(id: string, action: string) {
  return {
    id,
    action,
    status: "succeeded",
    targetType: "engagement",
    targetId: "eng-zy01",
    requestedBy: "operator",
    input: { engagementId: "eng-zy01" },
    artifactRefs: [],
    events: [
      {
        sequence: 1,
        level: "info",
        message: `${action} completed`,
        data: { status: "succeeded" }
      }
    ]
  };
}

function outboundApplyPreviewJob() {
  return {
    job: {
      id: "job-outbound-preview",
      action: "outbound_channel_apply_preview",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", chainId: "chain-1", mutation: false },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_outbound_channel.yml", "manifest.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "outbound channel apply preview rendered",
          data: {
            status: "Pending Core Apply",
            artifactTargets: {
              inventory: "ansible/inventory.ini",
              playbook: "ansible/apply_outbound_channel.yml",
              manifest: "manifest.json"
            },
            workspaceEvidence: {
              inventory: { target: "ansible/inventory.ini", byteCount: 120, sha256: "abc" },
              playbook: { target: "ansible/apply_outbound_channel.yml", byteCount: 240, sha256: "def" },
              manifest: { target: "manifest.json", byteCount: 360, sha256: "ghi" }
            }
          }
        }
      ]
    },
    workspace: {
      status: "Pending Core Apply",
      mutation: false,
      inventory: { target: "ansible/inventory.ini", byteCount: 120, sha256: "abc" },
      playbook: { target: "ansible/apply_outbound_channel.yml", byteCount: 240, sha256: "def" },
      manifest: { target: "manifest.json", byteCount: 360, sha256: "ghi" }
    }
  };
}

function backflipsApplyPreviewJob() {
  return {
    job: {
      id: "job-backflips-preview",
      action: "backflips_service_apply_preview",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", proxyId: "proxy01", mutation: false },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_backflips.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "backflips service apply preview rendered",
          data: {
            proxyId: "proxy01",
            workspaceEvidence: {
              inventory: { path: "ansible/inventory.ini", bytes: 120, content: "[selected_proxy]\nproxy01 ansible_host=192.168.2.11" },
              playbook: { path: "ansible/apply_backflips.yml", bytes: 240, content: "hosts: selected_proxy" },
              manifest: { path: "MANIFEST.json", bytes: 360, content: "{}" }
            },
            inboundChannels: [
              {
                channelId: "default-backflip",
                service: "SSH Backflips",
                terminatesOn: "proxy01",
                internalPort: "2222",
                status: "Configured"
              }
            ]
          }
        }
      ]
    },
    workspace: {
      status: "Pending Service Apply",
      mutation: false,
      inventory: { target: "ansible/inventory.ini", content: "[selected_proxy]\nproxy01 ansible_host=192.168.2.11" },
      playbook: { target: "ansible/apply_backflips.yml", content: "hosts: selected_proxy" },
      manifest: { target: "MANIFEST.json", content: "{}" }
    }
  };
}

function backflipsApplyJob() {
  return {
    job: {
      id: "job-backflips-apply",
      action: "backflips_service_apply",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", proxyId: "proxy01", mutation: true, confirmation: "redacted" },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_backflips.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "backflips service apply workspace rendered",
          data: {
            proxyId: "proxy01",
            workspaceEvidence: {
              inventory: { path: "ansible/inventory.ini", bytes: 120, content: "[selected_proxy]" },
              playbook: { path: "ansible/apply_backflips.yml", bytes: 240, content: "hosts: selected_proxy" },
              manifest: { path: "MANIFEST.json", bytes: 360, content: "{}" }
            }
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "backflips service Ansible apply succeeded",
          data: {
            status: "Configured",
            servicePlacements: [{ hostId: "proxy01", service: "SSH Backflips", status: "Configured" }],
            inboundChannels: [
              {
                channelId: "default-backflip",
                service: "SSH Backflips",
                terminatesOn: "proxy01",
                internalPort: "2222",
                status: "Configured"
              }
            ]
          }
        }
      ]
    },
    status: "Configured"
  };
}

function desktopApplyJob() {
  return {
    job: {
      id: "job-desktop-apply",
      action: "desktop_service_apply",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", desiredApps: [{ slug: "google-chrome", enabled: true }, { slug: "keepassxc", enabled: false }], mutation: true },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_desktop.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "Desktop service apply workspace rendered",
          data: {
            desiredApps: [{ slug: "google-chrome", enabled: true }, { slug: "keepassxc", enabled: false }],
            workspaceEvidence: {
              inventory: { path: "ansible/inventory.ini", bytes: 120, content: "[selected_homebase]" },
              playbook: { path: "ansible/apply_desktop.yml", bytes: 240, content: "hosts: selected_homebase" },
              manifest: { path: "MANIFEST.json", bytes: 360, content: "{}" }
            }
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "Desktop service Ansible apply succeeded",
          data: {
            status: "Configured",
            servicePlacements: [
              { hostId: "homebase", serviceId: "desktop-google-chrome", serviceType: "desktop-app", service: "Google Chrome", status: "Configured" },
              { hostId: "homebase", serviceId: "desktop-keepassxc", serviceType: "desktop-app", service: "KeePassXC", status: "Removed" }
            ]
          }
        }
      ]
    },
    status: "Configured",
    servicePlacements: [
      { hostId: "homebase", serviceId: "desktop-google-chrome", serviceType: "desktop-app", service: "Google Chrome", status: "Configured" },
      { hostId: "homebase", serviceId: "desktop-keepassxc", serviceType: "desktop-app", service: "KeePassXC", status: "Removed" }
    ]
  };
}

function desktopApplyRunningJob() {
  return {
    job: {
      id: "job-desktop-apply",
      action: "desktop_service_apply",
      status: "running",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", desiredApps: [{ slug: "google-chrome", enabled: true }, { slug: "keepassxc", enabled: false }], mutation: true },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_desktop.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "Desktop service apply workspace rendered",
          data: {}
        },
        {
          sequence: 2,
          level: "info",
          message: "Desktop service Ansible apply started",
          data: {}
        },
        {
          sequence: 3,
          level: "info",
          message: "Desktop service Ansible task started",
          data: { taskName: "Install Desktop app Google Chrome" }
        },
        {
          sequence: 4,
          level: "info",
          message: "Desktop service Ansible task completed",
          data: { taskName: "Install Desktop app Google Chrome", result: "changed" }
        }
      ]
    },
    status: "Running",
    servicePlacements: [
      { hostId: "homebase", serviceId: "desktop-google-chrome", serviceType: "desktop-app", service: "Google Chrome", status: "Installing" },
      { hostId: "homebase", serviceId: "desktop-keepassxc", serviceType: "desktop-app", service: "KeePassXC", status: "Removing" }
    ]
  };
}

function webStaticService() {
  return {
    engagementId: "eng-zy01",
    serviceId: "web-ff10",
    serviceType: "web-static",
    name: "ff10",
    proxyId: "proxy01",
    status: "Configured",
    config: {
      siteName: "ff10",
      domain: "ff10.example.invalid",
      internalPort: 8081,
      contentPath: "/opt/web/ff10/html/index.html",
      siteConfigPath: "/opt/web/ff10/conf/default.conf",
      composePath: "/opt/web/barragan-ff10.compose.yml"
    },
    applyJobId: "job-web-static-apply",
    createdAt: "2026-06-09T12:00:00+00:00",
    updatedAt: "2026-06-09T12:00:00+00:00"
  };
}

function webStaticApplyPreviewJob() {
  return {
    contentReview: { reviewJobId: "job-web-static-preview", state: "existing", fingerprint: "reviewed-content",
      defaultAction: "preserve", allowedActions: ["preserve", "restore-starter"], message: "Existing files will be kept unless you restore the starter page." },
    job: {
      id: "job-web-static-preview",
      action: "web_static_service_apply_preview",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", serviceId: "web-ff10", mutation: false },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_web_static.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "static web service apply preview rendered",
          data: {
            service: { serviceId: "web-ff10", service: "Static Web" },
            mutation: false
          }
        }
      ]
    },
    workspace: {
      status: "Pending Service Apply",
      mutation: false,
      inventory: { target: "ansible/inventory.ini", content: "[selected_proxy]\nproxy01 ansible_host=192.168.2.11" },
      playbook: { target: "ansible/apply_web_static.yml", content: "hosts: selected_proxy" },
      manifest: { target: "MANIFEST.json", content: "{}" },
      artifacts: [
        { target: "files/opt/web/ff10/html/index.html", content: "<html><body>hola ff10</body></html>\n" },
        { target: "files/opt/web/ff10/conf/default.conf", content: "listen 8081;" },
        { target: "files/opt/web/sites/ff10.compose.yml", content: "expose:\n  - \"8081\"" },
        { target: "files/opt/web/conf/barragan-ff10.conf", content: "front proxy reference" }
      ]
    },
    service: webStaticService()
  };
}

function webStaticApplyJob() {
  return {
    job: {
      id: "job-web-static-apply",
      action: "web_static_service_apply",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", serviceId: "web-ff10", mutation: true },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_web_static.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "static web service Ansible apply succeeded",
          data: {
            status: "Configured",
            servicePlacements: [{ hostId: "proxy01", service: "Static Web", status: "Configured", port: "8081" }]
          }
        }
      ]
    },
    service: webStaticService(),
    status: "Configured"
  };
}

function webStaticRemovePreviewJob() {
  return {
    job: {
      id: "job-web-static-remove-preview",
      action: "web_static_service_remove_preview",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", serviceId: "web-ff10", mutation: false },
      artifactRefs: ["ansible/inventory.ini", "ansible/remove_web_static.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "static web service remove preview rendered",
          data: {
            service: { serviceId: "web-ff10", service: "Static Web" },
            mutation: false
          }
        }
      ]
    },
    workspace: {
      status: "Pending Service Removal",
      mutation: false,
      inventory: { target: "ansible/inventory.ini", content: "[selected_proxy]\nproxy01 ansible_host=192.168.2.11" },
      playbook: { target: "ansible/remove_web_static.yml", content: "hosts: selected_proxy" },
      manifest: { target: "MANIFEST.json", content: "{}" },
      artifacts: []
    },
    service: webStaticService(),
    confirmationToken: "remove-web-ff10"
  };
}

function webStaticRemoveJob() {
  return {
    job: {
      id: "job-web-static-remove",
      action: "web_static_service_remove",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", serviceId: "web-ff10", mutation: true },
      artifactRefs: ["ansible/inventory.ini", "ansible/remove_web_static.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "static web service Ansible remove succeeded",
          data: {
            status: "Removed",
            servicePlacements: [{ hostId: "proxy01", service: "Static Web", status: "Removed", port: "8081" }]
          }
        }
      ]
    },
    service: {
      ...webStaticService(),
      status: "Removed",
      updatedAt: "2026-06-09T12:05:00+00:00"
    },
    status: "Removed"
  };
}

function inboundApplyPreviewJob() {
  const ingressAssessment = inboundIngressAssessment();
  const channel = {
    channelId: "c2-primary",
    domain: "c2.example.invalid",
    protocol: "HTTPS",
    mode: "tcp-forward",
    externalPort: "443",
    edge: "edge-zy01-us-sea-01",
    middle: "middle01-zy01",
    proxy: "proxy01-zy01",
    terminatesOn: "homebase-zy01",
    service: "Mythic",
    internalPort: "7443",
    purpose: "C2 ingress",
    status: "Pending Apply",
    validation: {
      listenerOrigin: "homebase-zy01",
      listenerCommand: ["sh", "-lc", "nc -l 127.0.0.1 7443"],
      listenerShellDisplay: "sh -lc nc -l 127.0.0.1 7443",
      probeOrigin: "operator",
      probeCommand: ["sh", "-lc", "printf 'barragan-inbound-c2-primary' | nc -N edge-zy01-us-sea-01 443"],
      probeShellDisplay: "sh -lc printf 'barragan-inbound-c2-primary' | nc -N edge-zy01-us-sea-01 443",
      expectedMarker: "barragan-inbound-c2-primary",
      status: "Not Run",
      detail: "Start the temporary listener on the termination host, send the marker through the edge, verify receipt, then remove the listener."
    },
    artifactTargets: {
      edgeStream: "/opt/inbound-channels/c2-primary/edge-443.stream.conf",
      middleStream: "/opt/inbound-channels/c2-primary/middle-443.stream.conf",
      proxyStream: "/opt/inbound-channels/c2-primary/proxy-443.stream.conf"
    },
    ingressAssessment
  };
  const artifacts = {
    edgeStream: { target: "/opt/inbound-channels/c2-primary/edge-443.stream.conf", content: "server middle01-zy01:443;" },
    middleStream: { target: "/opt/inbound-channels/c2-primary/middle-443.stream.conf", content: "server proxy01-zy01:443;" },
    proxyStream: { target: "/opt/inbound-channels/c2-primary/proxy-443.stream.conf", content: "server homebase-zy01:7443;" },
    validation: channel.validation,
    sketchNodeBoundary: {
      edgeNodeArtifacts: [],
      middleNodeArtifacts: [],
      reason: "Inbound sketch nodes receive only per-channel TCP forward configuration."
    }
  };
  return {
    job: {
      id: "job-inbound-preview",
      action: "inbound_channel_apply_preview",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", channelId: "c2-primary", mutation: false },
      artifactRefs: [],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "inbound channel apply preview rendered",
          data: {
            phase: "preview",
            mutation: false,
            inboundChannels: [channel],
            workspaceEvidence: artifacts,
            ingressAssessment
          }
        }
      ]
    },
    workspace: {
      status: "Pending Apply",
      mutation: false,
      channel,
      artifacts,
      ingressAssessment
    }
  };
}

function inboundIngressAssessment() {
  return {
    status: "allowed",
    applyAllowed: true,
    protocol: "tcp",
    externalPort: 443,
    proxyRelayPort: 443,
    terminationPort: 7443,
    blockedChecks: [],
    blockingReasons: [],
    summary: "No blocking ingress checks were found; validation is still required.",
    checks: [
      {
        id: "edge-provider-ingress",
        scope: "edgeProviderIngress",
        label: "Edge provider ingress",
        status: "unknown",
        protocol: "tcp",
        port: 443,
        host: "edge-zy01-us-sea-01",
        detail: "Provider ingress must be confirmed for the selected edge."
      },
      {
        id: "edge-host-firewall",
        scope: "edgeHostFirewall",
        label: "Edge host firewall",
        status: "managed",
        protocol: "tcp",
        port: 443,
        host: "edge-zy01-us-sea-01",
        detail: "Barragan apply manages the selected edge host firewall."
      },
      {
        id: "core-proxy-cloud-ingress",
        scope: "coreProxyCloudIngress",
        label: "Core proxy cloud ingress",
        status: "allowed",
        protocol: "tcp",
        port: 443,
        host: "proxy01-zy01",
        detail: "Selected core proxy relay port 443/tcp is inside the current pilot core proxy ingress pool."
      }
    ]
  };
}

function inboundApplyJob() {
  const channel = inboundApplyPreviewJob().workspace.channel;
  return {
    job: {
      id: "job-inbound-apply",
      action: "inbound_channel_apply",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", channelId: "c2-primary", mutation: true, confirmation: "redacted" },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_inbound_channel.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "inbound channel apply workspace rendered",
          data: {
            channelId: "c2-primary",
            status: "Pending Apply",
            workspaceEvidence: {
              inventory: { target: "ansible/inventory.ini" },
              playbook: { target: "ansible/apply_inbound_channel.yml" },
              manifest: { target: "MANIFEST.json" }
            }
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "inbound channel validation pending",
          data: {
            channelId: "c2-primary",
            status: "Pending Validation",
            validationRan: false,
            inboundChannels: [{ ...channel, status: "Pending Validation", validation: { ...channel.validation, status: "Pending Validation" } }]
          }
        }
      ]
    },
    status: "Pending Validation"
  };
}

function inboundValidateJob() {
  const channel = inboundApplyPreviewJob().workspace.channel;
  return {
    job: {
      id: "job-inbound-validate",
      action: "inbound_channel_validation",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", channelId: "c2-primary", mutation: false, confirmation: "redacted" },
      artifactRefs: ["ansible/inventory.ini", "ansible/validate_inbound_channel.yml", "MANIFEST.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "inbound channel validation workspace rendered",
          data: {
            channelId: "c2-primary",
            status: "Pending Validation",
            workspaceEvidence: {
              inventory: { target: "ansible/inventory.ini" },
              playbook: { target: "ansible/validate_inbound_channel.yml" },
              manifest: { target: "MANIFEST.json" }
            }
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "inbound channel validation succeeded",
          data: {
            channelId: "c2-primary",
            status: "Validated",
            validationEvidence: {
              status: "Validated",
              expectedMarker: "barragan-inbound-c2-primary",
              validationScope: "edge-local ingress route",
              externalIngressVerified: false,
              probeOrigin: "selected_edge"
            },
            inboundChannels: [{ ...channel, status: "Validated", validation: { ...channel.validation, status: "Validated" } }]
          }
        }
      ]
    },
    status: "Validated"
  };
}

function outboundApplyJob() {
  return {
    job: {
      id: "job-outbound-apply",
      action: "outbound_channel_apply",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", chainId: "chain-1", mutation: true, confirmation: "redacted" },
      artifactRefs: ["ansible/inventory.ini", "ansible/apply_outbound_channel.yml", "manifest.json"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "outbound channel apply workspace rendered",
          data: {
            status: "Pending Core Apply",
            artifactTargets: {
              inventory: "ansible/inventory.ini",
              playbook: "ansible/apply_outbound_channel.yml",
              manifest: "manifest.json"
            },
            workspaceEvidence: {
              inventory: { target: "ansible/inventory.ini", byteCount: 120, sha256: "abc" },
              playbook: { target: "ansible/apply_outbound_channel.yml", byteCount: 240, sha256: "def" },
              manifest: { target: "manifest.json", byteCount: 360, sha256: "ghi" }
            }
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "outbound channel validation pending",
          data: { status: "Pending Validation", validationRan: false }
        }
      ]
    },
    status: "Pending Validation"
  };
}

function outboundValidateJob() {
  return {
    job: {
      id: "job-outbound-validate",
      action: "outbound_channel_validation",
      status: "succeeded",
      targetType: "engagement",
      targetId: "eng-zy01",
      requestedBy: "operator",
      input: { engagementId: "eng-zy01", chainId: "chain-1", confirmation: "redacted" },
      artifactRefs: ["ansible/inventory.ini"],
      events: [
        {
          sequence: 1,
          level: "info",
          message: "outbound channel validation workspace rendered",
          data: {
            status: "Pending Validation",
            workspaceEvidence: {
              inventory: { target: "ansible/inventory.ini", byteCount: 80, sha256: "jkl" }
            }
          }
        },
        {
          sequence: 2,
          level: "info",
          message: "outbound channel validation succeeded",
          data: {
            status: "Validated",
            validationEvidence: {
              status: "Validated",
              observedPublicIp: "203.0.113.30",
              expectedPublicIp: "203.0.113.30"
            }
          }
        }
      ]
    },
    status: "Validated"
  };
}

function opsecCapabilityWorkspace() {
  return {
    workspace: {
      engagementId: "eng-zy01",
      slug: "zy01",
      path: "/opt/engagements/zy01",
      status: "capabilities-configured",
      profileId: "standard-rti",
      metadata: {}
    },
    profileResolution: {
      source: { path: "/tmp/redteam-infra", kind: "git", warning: "" },
      profile: { id: "standard-rti", name: "Standard RTI", description: "Default RTI profile." },
      status: "passed",
      hostClasses: {
        homebase: {
          essential: [],
          default: [],
          optional: [
            {
              id: "opsec",
              name: "OPSEC network restrictions",
              description: "Block Homebase outbound connections to configured IPs or CIDRs.",
              hostClass: "homebase",
              classification: "optional",
              resolution: "catalog",
              executable: true,
              selected: false,
              locked: false,
              implementation: { type: "role", path: "ansible/roles/opsec", role: "opsec" },
              operator: { visible: true, selectable: true }
            }
          ],
          internal: [],
          unsupported: []
        }
      },
      summary: { total: 1, catalog: 1, selected: 0 },
      warnings: []
    },
    overrides: { deselectedDefaults: [], selectedOptionals: [] }
  };
}

function backflipsCapabilityWorkspace() {
  return {
    workspace: null,
    profileResolution: {
      source: { path: "/tmp/redteam-infra", kind: "git", warning: "" },
      profile: { id: "standard-rti", name: "Standard RTI", description: "Default RTI profile." },
      status: "passed",
      hostClasses: {
        proxy: {
          essential: [],
          default: [],
          optional: [
            {
              id: "barragan.backflips-v2",
              name: "Backflips V2",
              description: "Install Backflips prerequisites; listeners remain operator-managed.",
              hostClass: "proxy",
              classification: "optional",
              resolution: "catalog",
              executable: false,
              selected: false,
              locked: false,
              implementation: { type: "barragan-native", path: "", role: "" },
              operator: { visible: true, selectable: false, configurable: true }
            }
          ],
          internal: [],
          unsupported: []
        }
      },
      summary: { total: 1, catalog: 1, selected: 0 },
      warnings: []
    },
    nativeState: {
      backflips: {
        configureRoute: "backflips",
        proxies: [
          { proxyId: "proxy01", status: "Waiting", jobId: "" },
          { proxyId: "proxy02", status: "Ready", jobId: "job-backflips-proxy02" }
        ]
      }
    },
    overrides: { deselectedDefaults: [], selectedOptionals: [] }
  };
}

function managedCapabilityWorkspace() {
  const entry = (id: string, name: string, description: string) => ({
    id,
    name,
    description,
    hostClass: "proxy",
    classification: "optional",
    resolution: "catalog",
    executable: false,
    selected: false,
    locked: false,
    implementation: { type: "barragan-native", path: "", role: "" },
    operator: { visible: true, selectable: false, configurable: true }
  });
  return {
    workspace: null,
    profileResolution: {
      source: { path: "/tmp/redteam-infra", kind: "git", warning: "" },
      profile: { id: "standard-rti", name: "Standard RTI", description: "Default RTI profile." },
      status: "passed",
      hostClasses: {
        proxy: {
          essential: [],
          default: [],
          optional: [
            entry("barragan.static-web-site", "Static Web", "Manage Barragan-owned proxy-local sites and publication workflows."),
            entry("barragan.custom-listener", "Custom Listener", "Track an operator-managed listener for inbound routing.")
          ],
          internal: [],
          unsupported: []
        }
      },
      summary: { total: 2, catalog: 2, selected: 0 },
      warnings: []
    },
    nativeState: {
      staticWeb: { claimed: false, claimingCount: 0, claimingSiteIds: [], selected: false, implied: false, reason: "" }
    },
    overrides: { deselectedDefaults: [], selectedOptionals: [] }
  };
}

function capabilityApplyState(
  status: "unsaved" | "saved_ready" | "applying" | "applied" | "blocked" | "partial" | "failed" = "unsaved",
  children: Array<{
    kind: "optional_roles" | "desktop";
    status: "pending" | "running" | "succeeded" | "failed" | "blocked" | "not_required";
    jobId: string;
    detail: string;
  }> = []
) {
  return {
    status,
    selectionFingerprint: "selection-fingerprint",
    renderedInputFingerprint: "rendered-input-fingerprint",
    preparedAt: "2026-08-20T00:00:00+00:00",
    startedAt: status === "unsaved" || status === "saved_ready" || status === "blocked" ? "" : "2026-08-20T00:01:00+00:00",
    finishedAt: ["applied", "partial", "failed"].includes(status) ? "2026-08-20T00:02:00+00:00" : "",
    parentJobId: status === "unsaved" || status === "saved_ready" || status === "blocked" ? "" : "job-capability-apply",
    errors: [],
    children
  };
}

function capabilityApplyJob(kind: "desktop" | "optional") {
  const childMessage = kind === "desktop" ? "Desktop Ansible apply succeeded" : "Optional-role Ansible apply succeeded";
  return {
    id: "job-capability-apply",
    action: "capability_apply",
    status: "succeeded",
    targetType: "engagement",
    targetId: "eng-zy01",
    requestedBy: "operator",
    input: { engagementId: "eng-zy01" },
    artifactRefs: [],
    events: [
      { sequence: 1, level: "info", message: "Saved capability apply started", data: {} },
      { sequence: 2, level: "info", message: childMessage, data: {} }
    ]
  };
}

function desktopCapabilityWorkspace(
  overrides: { deselectedDefaults?: Array<{ hostClass: string; id: string }>; selectedOptionals?: Array<{ hostClass: string; id: string }> } = {},
  applyState = capabilityApplyState()
) {
  const deselectedDefaults = overrides.deselectedDefaults ?? [];
  const selectedOptionals = overrides.selectedOptionals ?? [];
  const entry = (id: string, name: string, classification: "default" | "optional") => ({
    id,
    name,
    description: `${name} desktop capability.`,
    hostClass: "homebase",
    classification,
    resolution: "catalog",
    executable: true,
    selected: classification === "default"
      ? !deselectedDefaults.some((row) => row.hostClass === "homebase" && row.id === id)
      : selectedOptionals.some((row) => row.hostClass === "homebase" && row.id === id),
    locked: false,
    implementation: { type: "role", path: `ansible/roles/${id}`, role: id },
    operator: { visible: true, selectable: true }
  });
  return {
    workspace: {
      engagementId: "eng-zy01",
      slug: "zy01",
      path: "/opt/engagements/zy01",
      status: "capabilities-configured",
      profileId: "standard-rti",
      metadata: {}
    },
    profileResolution: {
      source: { path: "/tmp/redteam-infra", kind: "git", warning: "" },
      profile: { id: "standard-rti", name: "Standard RTI", description: "Default RTI profile." },
      status: "passed",
      hostClasses: {
        homebase: {
          essential: [],
          default: [entry("google-chrome", "Google Chrome", "default"), entry("keepassxc", "KeePassXC", "default")],
          optional: [],
          internal: [],
          unsupported: []
        }
      },
      summary: { total: 2, catalog: 2, selected: 2 - deselectedDefaults.length },
      warnings: []
    },
    applyState,
    overrides: { deselectedDefaults, selectedOptionals }
  };
}

function optionalRoleCapabilityWorkspace(
  selectedOptionals: Array<{ hostClass: string; id: string }> = [],
  applyState = capabilityApplyState()
) {
  const selected = selectedOptionals.some((row) => row.hostClass === "homebase" && row.id === "go-simple-upload-server");
  return {
    workspace: {
      engagementId: "eng-zy01",
      slug: "zy01",
      path: "/opt/engagements/zy01",
      status: "capabilities-configured",
      profileId: "standard-rti",
      metadata: {}
    },
    profileResolution: {
      source: { path: "/tmp/redteam-infra", kind: "git", warning: "" },
      profile: { id: "standard-rti", name: "Standard RTI", description: "Default RTI profile." },
      status: "passed",
      hostClasses: {
        homebase: {
          essential: [],
          default: [],
          optional: [
            {
              id: "go-simple-upload-server",
              name: "Go Simple Upload Server",
              description: "Run the stock Redteam-infra upload server on Homebase.",
              hostClass: "homebase",
              classification: "optional",
              resolution: "catalog",
              executable: true,
              selected,
              locked: false,
              implementation: { type: "role", path: "ansible/roles/go_simple_upload_server", role: "go_simple_upload_server" },
              operator: { visible: true, selectable: true }
            }
          ],
          internal: [],
          unsupported: []
        }
      },
      summary: { total: 1, catalog: 1, selected: selected ? 1 : 0 },
      warnings: []
    },
    applyState,
    overrides: { deselectedDefaults: [], selectedOptionals }
  };
}

function reconciliationPlan(homebaseRoles: Array<{ id: string; role: string }>) {
  return {
    selectedCount: homebaseRoles.length,
    executableCount: homebaseRoles.length,
    roleCount: homebaseRoles.length,
    rolesByHostClass: { common: [], homebase: homebaseRoles, proxy: [], elk: [] },
    targetHostClasses: homebaseRoles.length ? ["homebase"] : [],
    availableHostClasses: ["homebase", "proxy"],
    skipped: [],
    warnings: [],
    errors: []
  };
}

function opsecService(status: string) {
  return {
    engagementId: "eng-zy01",
    serviceId: "opsec-network-restrictions",
    serviceType: "opsec-network-restrictions",
    name: "OPSEC Network Restrictions",
    proxyId: "homebase",
    status,
    config: { enabled: status !== "Disabled", destinations: [], notes: "", purpose: "" },
    applyJobId: status === "Disabled" ? "" : "job-opsec-apply",
    createdAt: "2026-07-20T00:00:00+00:00",
    updatedAt: "2026-07-20T00:00:00+00:00"
  };
}

function opsecJob(status: "running" | "succeeded") {
  return {
    id: "job-opsec-apply",
    action: "opsec_network_restrictions_apply",
    status,
    targetType: "engagement",
    targetId: "eng-zy01",
    requestedBy: "operator",
    input: { engagementId: "eng-zy01", enabled: true, cidrs: ["10.10.0.0/24", "203.0.113.7"], mutation: true },
    artifactRefs: ["ansible/inventory.ini", "ansible/apply_opsec_network_restrictions.yml", "MANIFEST.json"],
    events: [
      {
        sequence: 1,
        level: "info",
        message: "OPSEC network restrictions workspace rendered",
        data: { inventoryTargets: ["selected_homebase"] }
      },
      {
        sequence: 2,
        level: "info",
        message: "OPSEC network restrictions Ansible apply started",
        data: { inventoryTargets: ["selected_homebase"] }
      },
      ...(status === "succeeded"
        ? [
            {
              sequence: 3,
              level: "info",
              message: "OPSEC network restrictions Ansible apply succeeded",
              data: { commandResult: { returncode: 0, stdout: "ok\n", stderr: "" } }
            }
          ]
        : [])
    ]
  };
}

describe("published teardown identity handoff", () => {
  function routes(operations: unknown, options: { coreResponse?: () => Promise<Response>; operationsResponse?: () => unknown; parent?: unknown } = {}) {
    const fixture = publishedTeardownFixture();
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary(fixture.engagement)] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith(`/api/engagements/${fixture.engagement.id}/operations`)) return Promise.resolve(jsonResponse({ operations: options.operationsResponse?.() ?? operations }));
      if (url.endsWith(`/runs/${fixture.parent.id}`)) return Promise.resolve(jsonResponse({ job: options.parent ?? fixture.parent }));
      if (url.endsWith(`/runs/${fixture.core.id}`)) return options.coreResponse?.() ?? Promise.resolve(jsonResponse({ job: fixture.core }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    return fetchMock;
  }

  it("blocks ambiguous exact-generation parents instead of displaying deployment logs", async () => {
    const fixture = publishedTeardownFixture();
    const calls = routes({ ...fixture.operations, teardownJob: null, teardownSelection: { state: "ambiguous" } });
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Multiple teardown records match");
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
    expect(calls.mock.calls.some(([url]) => String(url).endsWith(`/runs/${fixture.core.id}`))).toBe(false);
  });

  it("treats a verified terminal teardown as history", async () => {
    const fixture = publishedTeardownFixture({ status: "succeeded", phase: "complete", completed: 9 });
    routes(fixture.operations);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Infrastructure Destroyed" })).toBeInTheDocument();
    const historical = screen.getByLabelText("Historical core infrastructure");
    expect(historical).toHaveTextContent(fixture.core.id);
    expect(historical).not.toHaveTextContent(fixture.parent.id);
    expect(fixture.parent.input.phase).toBe("lifecycle_reconciliation");
    expect(fixture.parent.progress).toEqual({ completed: 9, total: 9 });
    expect(fixture.parent.activeChild).toBeNull();
    expect(fixture.parent.dispatch.status).toBe("succeeded");
    expect(fixture.parent.dispatch.claimState).not.toBe("live");
    expect(screen.queryByLabelText("Teardown worker progress")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  });

  it("keeps the open cleanup console on its terminal parent after settled Operations refresh", async () => {
    let fixture = publishedTeardownFixture();
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary(fixture.engagement)] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith(`/api/engagements/${fixture.engagement.id}/operations`)) return Promise.resolve(jsonResponse({ operations: fixture.operations }));
      if (url.endsWith(`/runs/${fixture.parent.id}`)) return Promise.resolve(jsonResponse({ job: fixture.parent }));
      if (url.endsWith(`/runs/${fixture.core.id}`)) return Promise.resolve(jsonResponse({ job: fixture.core }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByLabelText("Teardown worker progress")).toHaveTextContent("Worker claim is active");
    fireEvent.click(screen.getByRole("button", { name: "Open Console" }));
    fixture = publishedTeardownFixture({ status: "succeeded" });
    expect(await screen.findByRole("heading", { name: "Infrastructure Destroyed" }, { timeout: 4000 })).toBeInTheDocument();
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 400)); });
    const console = screen.getByLabelText("Infrastructure teardown console");
    expect(console).toHaveTextContent("9/9");
    expect(console).toHaveTextContent("published mixed teardown complete");
    expect(console).not.toHaveTextContent("Historical deployment log");
    expect(screen.queryByLabelText("Infrastructure deployment console")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/runs/${fixture.core.id}`))).toBe(false);
    expect(screen.getByLabelText("Historical core infrastructure")).toHaveTextContent(fixture.core.id);
  });

  it("keeps terminal elapsed time when the raw parent GET omits dispatch metadata", async () => {
    let fixture = publishedTeardownFixture();
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary(fixture.engagement)] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith(`/api/engagements/${fixture.engagement.id}/operations`)) return Promise.resolve(jsonResponse({
        operations: { ...fixture.operations, teardownJob: { ...fixture.operations.teardownJob, dispatch: fixture.parent.dispatch } }
      }));
      if (url.endsWith(`/runs/${fixture.parent.id}`)) {
        // The terminal response keeps phase/progress but can lack the dispatch
        // projection after its final refresh; Operations still supplies it.
        const { dispatch, ...terminalWithoutDispatch } = fixture.parent;
        return Promise.resolve(jsonResponse({ job: fixture.parent.status === "succeeded" ? terminalWithoutDispatch : fixture.parent }));
      }
      if (url.endsWith(`/runs/${fixture.core.id}`)) return Promise.resolve(jsonResponse({ job: fixture.core }));
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByLabelText("Teardown worker progress")).toHaveTextContent("Worker claim is active");
    fireEvent.click(screen.getByRole("button", { name: "Open Console" }));
    fixture = publishedTeardownFixture({ status: "succeeded" });
    fixture.parent.dispatch.startedAt = "2026-10-26T12:00:00Z";
    fixture.parent.dispatch.finishedAt = "2026-10-26T12:40:10Z";
    expect(await screen.findByRole("heading", { name: "Infrastructure Destroyed" }, { timeout: 4000 })).toBeInTheDocument();
    const console = screen.getByLabelText("Infrastructure teardown console");
    await waitFor(() => expect(console).toHaveTextContent("Elapsed: 40m 10s"));
    expect(console).toHaveTextContent("9/9");
    expect(console).toHaveTextContent("Last activity: not reported");
    expect(console).not.toHaveTextContent("Historical deployment log");
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 1100)); });
    expect(console).toHaveTextContent("Elapsed: 40m 10s");
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/runs/${fixture.core.id}`))).toBe(false);
  });

  it("shows an unknown worker claim without offering another teardown", async () => {
    const fixture = publishedTeardownFixture();
    routes(fixture.operations, { parent: { ...fixture.parent, dispatch: { status: "unknown", claimState: "unknown", heartbeatAt: null } } });
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByLabelText("Teardown worker progress")).toHaveTextContent("do not start another teardown");
    fireEvent.click(screen.getByRole("button", { name: "Open Console" }));
    expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("Elapsed: not reported");
    expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("Last activity: not reported");
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Tear Down Infrastructure" })).toBeDisabled();
  });

  it.each(["initial", "unpublished-six"] as const)("keeps the explicit %s cleanup display contract compatible", async (source) => {
    const fixture = publishedTeardownFixture({ source });
    routes(fixture.operations, { parent: fixture.parent });
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByLabelText("Teardown worker progress")).toHaveTextContent("Worker claim is active");
    expect(screen.queryByText("Cleanup recovery unavailable")).not.toBeInTheDocument();
  });

  it.each(["modern-flat", "nested-untagged", "mixed", "crossed-plan", "crossed-engagement", "crossed-parent", "unknown-kind", "duplicate-provider"])("blocks malformed %s published source without falling back to core logs", async (drift) => {
    const fixture = publishedTeardownFixture();
    const parent = structuredClone(fixture.parent);
    const input = parent.input as Record<string, any>;
    if (drift === "modern-flat") input.publishedSource = input.publishedSource.six_node_source;
    else if (drift === "nested-untagged") delete input.sourceKind;
    else if (drift === "mixed") input.publishedSource.core_job_id = input.coreJobId;
    else if (drift === "crossed-plan") input.publishedSource.six_node_source.core_plan_id = "plan-other";
    else if (drift === "crossed-engagement") input.publishedSource.six_node_source.engagement_id = "eng-other";
    else if (drift === "crossed-parent") input.publishedSource.parent_job_id = "job-other";
    else if (drift === "unknown-kind") input.sourceKind = "future-six-v99";
    else input.publishedSource.six_node_source.provider_order = ["linode", "linode"];
    const calls = routes(fixture.operations, { parent });
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Cleanup recovery unavailable");
    expect(screen.queryByLabelText("Teardown worker progress")).not.toBeInTheDocument();
    expect(calls.mock.calls.some(([url]) => String(url).endsWith(`/runs/${fixture.core.id}`))).toBe(false);
    expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
  });

  it.each(["accepted", "server-error", "unclassified-400"] as const)("handles %s after typed confirmation POST without a deferred core GET becoming cleanup progress", async (outcome) => {
    const fixture = publishedTeardownFixture();
    const core = { ...pilotRunJob(fixture.engagement.id), id: fixture.core.id };
    const preview = { snapshotId: "example-reviewed-snapshot", engagementId: fixture.engagement.id,
      engagementName: "Example fixture", confirmationPhrase: "teardown-example-fixture", parentJobId: null,
      orderedScope: [{ id: "core", label: "Example fixture core infrastructure", items: [] }] };
    let releaseCore!: (response: Response) => void;
    const pendingCore = new Promise<Response>((resolve) => { releaseCore = resolve; });
    let posted = false;
    let acknowledge!: (response: Response) => void;
    const pendingAcknowledgement = new Promise<Response>((resolve) => { acknowledge = resolve; });
    let projectParent!: (response: Response) => void;
    const pendingParentDetail = new Promise<Response>((resolve) => { projectParent = resolve; });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary(fixture.engagement)] }));
      if (url.endsWith("/api/dashboard")) return Promise.resolve(jsonResponse({ dashboard: null }));
      if (url.endsWith(`/api/engagements/${fixture.engagement.id}/operations`)) return Promise.resolve(jsonResponse({ operations: posted
        ? fixture.operations : { ...operationsOverview(""), engagementId: fixture.engagement.id, lifecycle: { state: "deployed", terminal: false },
            coreJob: fixture.core, teardownJob: null, teardownSelection: { state: "absent" } } }));
      if (url.includes("/api/jobs?")) return Promise.resolve(jsonResponse({ jobs: [{ id: core.id, action: core.action,
        status: core.status, target: `engagement:${fixture.engagement.id}`, createdAt: "2026-10-26T00:00:00Z" }],
        pagination: { total: 1, limit: 50, offset: 0, hasMore: false } }));
      if (url.endsWith(`/api/jobs/${core.id}`)) return Promise.resolve(jsonResponse({ job: core }));
      if (url.endsWith(`/runs/${core.id}/teardown`)) {
        if (init?.method === "POST") {
          return pendingAcknowledgement;
        }
        return Promise.resolve(jsonResponse({ teardown: preview }));
      }
      if (url.endsWith(`/runs/${fixture.parent.id}`)) return pendingParentDetail;
      if (url.endsWith(`/runs/${core.id}`)) return pendingCore;
      if (url.includes("/readiness")) return Promise.resolve(jsonResponse({ readiness: pilotReadiness() }));
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/runs/${core.id}`))).toBe(true));
    // Loading the already-recorded deployment from Jobs supplies the held
    // deployment while its earlier Infrastructure GET remains outstanding.
    fireEvent.click(screen.getByRole("button", { name: "Jobs" }));
    fireEvent.click(await screen.findByRole("button", { name: `Select job ${core.id}` }));
    fireEvent.click(await screen.findByRole("button", { name: "Load In Engagement" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Tear Down Infrastructure" })).toBeEnabled());
    fireEvent.click(screen.getByRole("button", { name: "Tear Down Infrastructure" }));
    await screen.findByText(/Example fixture core infrastructure/);
    fireEvent.change(screen.getByLabelText("Confirm tear down phrase"), { target: { value: preview.confirmationPhrase } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm Tear Down" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${core.id}/teardown`,
      expect.objectContaining({ method: "POST", body: JSON.stringify({ confirmation: preview.confirmationPhrase, snapshotId: preview.snapshotId }) })));
    const waitingConsole = screen.getByLabelText("Infrastructure teardown console");
    expect(screen.getByLabelText("Teardown request progress")).toHaveTextContent("Waiting for the cleanup job");
    expect(waitingConsole).not.toHaveTextContent("pilot Standard RTI run finished");
    expect(waitingConsole).not.toHaveTextContent("Completed successfully");
    expect(waitingConsole).not.toHaveTextContent("Teardown scope accepted");
    expect(waitingConsole).toHaveTextContent("Elapsed: not reported");
    expect(screen.queryByLabelText("Current core infrastructure")).not.toBeInTheDocument();
    await act(async () => { releaseCore(jsonResponse({ job: core })); });
    expect(waitingConsole).not.toHaveTextContent("pilot Standard RTI run finished");
    // POST's producer returns raw JobRunDetail; augmented progress arrives only
    // from the exact parent's pilot GET/Operations projection.
    if (outcome !== "accepted") {
      const status = outcome === "unclassified-400" ? 400 : 500;
      await act(async () => { acknowledge(new Response(JSON.stringify({ errors: ["published mixed cleanup review changed; review again"] }),
        { status, headers: { "Content-Type": "application/json" } })); });
      expect(await screen.findByRole("alert")).toHaveTextContent("Teardown could not be confirmed");
      const unconfirmedConsole = screen.getByLabelText("Infrastructure teardown console");
      expect(unconfirmedConsole).not.toHaveTextContent("pilot Standard RTI run finished");
      expect(unconfirmedConsole).not.toHaveTextContent("Completed successfully");
      expect(screen.queryByRole("button", { name: "Tear Down Infrastructure" })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Retry Tear Down" })).not.toBeInTheDocument();
      expect(fetchMock.mock.calls.filter(([url, init]) => String(url).endsWith("/teardown") && init?.method === "POST")).toHaveLength(1);
      // A later authoritative parent may still appear after the lost response.
      // Read-only refresh can join it; an absent snapshot never authorizes retry.
      posted = true;
      await act(async () => { projectParent(jsonResponse({ job: fixture.parent })); });
      fireEvent.click(within(unconfirmedConsole).getByRole("button", { name: "Close" }));
      fireEvent.click(screen.getByRole("button", { name: "Overview" }));
      await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith(`/runs/${fixture.parent.id}`))).toBe(true));
      fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
      expect(await screen.findByLabelText("Teardown worker progress")).toHaveTextContent("Worker claim is active");
      expect(fetchMock.mock.calls.filter(([url, init]) => String(url).endsWith("/teardown") && init?.method === "POST")).toHaveLength(1);
      return;
    }
    const { phase, progress, dispatch, activeChild, activeChildState, ...rawParent } = fixture.parent;
    posted = true;
    await act(async () => { acknowledge(jsonResponse({ job: { ...rawParent,
      input: { ...rawParent.input, phase: "awaiting_both_destroy_plans" } } })); });
    expect(await screen.findByLabelText("Teardown worker progress")).toHaveTextContent("Saving both provider destroy plans");
    expect(screen.getByLabelText("Infrastructure teardown console")).not.toHaveTextContent("Completed successfully");
    await act(async () => { projectParent(jsonResponse({ job: fixture.parent })); });
    await waitFor(() => expect(screen.getByLabelText("Teardown worker progress")).toHaveTextContent("Saved core plan execution is running"));
    await waitFor(() => expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("Example fixture: published mixed cleanup review queued"));
    expect(screen.getByLabelText("Infrastructure teardown console")).not.toHaveTextContent("pilot Standard RTI run finished");
    expect(screen.queryByText("Cleanup recovery unavailable")).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.filter(([url, init]) => String(url).endsWith("/teardown") && init?.method === "POST")).toHaveLength(1);
  });

  it("keeps the exact parent when an earlier core GET resolves after Operations handoff", async () => {
    const fixture = publishedTeardownFixture();
    let releaseCore!: (response: Response) => void;
    const pendingCore = new Promise<Response>((resolve) => { releaseCore = resolve; });
    let handoff = false;
    const calls = routes(fixture.operations, { coreResponse: () => pendingCore, operationsResponse: () => !handoff
      ? { ...fixture.operations, lifecycle: { state: "deployed", terminal: false }, teardownJob: null, teardownSelection: { state: "absent" } }
      : fixture.operations });
    render(<App />);
    await waitFor(() => expect(screen.getByText("ready")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    await waitFor(() => expect(calls.mock.calls.some(([url]) => String(url).endsWith(`/runs/${fixture.core.id}`))).toBe(true));
    handoff = true;
    fireEvent.click(screen.getByRole("button", { name: "Infrastructure" }));
    expect(await screen.findByRole("heading", { name: "Infrastructure teardown in progress" })).toBeInTheDocument();
    releaseCore(jsonResponse({ job: fixture.core }));
    await waitFor(() => expect(screen.getByLabelText("Teardown worker progress")).toHaveTextContent("Saved core plan execution is running"));
    fireEvent.click(screen.getByRole("button", { name: "Open Console" }));
    expect(screen.getByLabelText("Infrastructure teardown console")).toHaveTextContent("Example fixture: published mixed cleanup review queued");
    expect(screen.getByLabelText("Infrastructure teardown console")).not.toHaveTextContent("Historical deployment log");
  });
});


describe("published teardown dispatch clocks", () => {
  it("uses dispatch time while the canonical parent remains queued", () => {
    const { parent } = publishedTeardownFixture();
    const now = Date.parse("2026-10-26T12:02:00Z");
    const job = { ...parent, dispatch: { ...parent.dispatch, startedAt: "2026-10-26T12:00:00Z", heartbeatAt: "2026-10-26T12:01:55Z" } };
    expect(publishedTeardownTiming(job, now)).toEqual({ elapsedSeconds: 120, lastActivitySeconds: 5 });
  });
  it("freezes verified terminal elapsed time and leaves missing heartbeat unreported", () => {
    const { parent } = publishedTeardownFixture({ status: "succeeded" });
    expect(publishedTeardownTiming(parent, Date.parse("2026-10-26T13:00:00Z"))).toEqual({ elapsedSeconds: 120, lastActivitySeconds: null });
    expect(publishedTeardownTiming(parent, Date.parse("2026-10-26T14:00:00Z"))).toEqual({ elapsedSeconds: 120, lastActivitySeconds: null });
  });
  it("reports missing or invalid dispatch timestamps instead of zero", () => {
    const { parent } = publishedTeardownFixture();
    expect(publishedTeardownTiming({ ...parent, dispatch: undefined }, Date.now())).toEqual({ elapsedSeconds: null, lastActivitySeconds: null });
    expect(publishedTeardownTiming({ ...parent, dispatch: { ...parent.dispatch, startedAt: "invalid", heartbeatAt: "invalid" } }, Date.now())).toEqual({ elapsedSeconds: null, lastActivitySeconds: null });
  });
  it("uses only the exact same-engagement terminal Operations dispatch for a raw parent", () => {
    const { parent, operations } = publishedTeardownFixture({ status: "succeeded" });
    const raw = { ...parent, dispatch: undefined };
    const projected = { ...operations, teardownJob: { ...operations.teardownJob,
      recoveryState: "complete" as const, dispatch: { ...parent.dispatch,
        startedAt: "2026-10-26T12:00:00Z", finishedAt: "2026-10-26T12:40:10Z" } } };
    const now = Date.parse("2026-10-26T14:00:00Z");
    expect(publishedTeardownTiming(raw, now, projected)).toEqual({ elapsedSeconds: 2410, lastActivitySeconds: null });
    expect(publishedTeardownTiming(raw, now + 3_600_000, projected)).toEqual({ elapsedSeconds: 2410, lastActivitySeconds: null });
    const unrelated = [
      { ...projected, engagementId: "eng-other" },
      { ...projected, teardownSelection: { state: "ambiguous" as const } },
      { ...projected, teardownJob: { ...projected.teardownJob, id: "job-other" } },
      { ...projected, teardownJob: { ...projected.teardownJob, action: "engagement_comprehensive_teardown" } },
      { ...projected, teardownJob: { ...projected.teardownJob, recoveryState: "blocked" as const } },
      { ...projected, teardownJob: { ...projected.teardownJob, status: "queued" } },
      { ...projected, teardownJob: { ...projected.teardownJob,
        dispatch: { ...projected.teardownJob.dispatch, status: "running" } } }
    ];
    for (const other of unrelated) {
      expect(publishedTeardownTiming(raw, now, other)).toEqual({ elapsedSeconds: null, lastActivitySeconds: null });
    }
    expect(raw.dispatch).toBeUndefined();
  });
});


describe("Static Web content review", () => {
  async function openSite(options: { state?: "empty" | "existing"; inspectionError?: boolean; applyError?: boolean; deferred?: Promise<Response> } = {}) {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/templates")) return Promise.resolve(jsonResponse({ templates: [] }));
      if (url.endsWith("/api/engagements?scope=all")) return Promise.resolve(jsonResponse({ engagements: [engagementSummary()] }));
      if (url.endsWith("/api/jobs")) return Promise.resolve(jsonResponse({ jobs: [] }));
      if (url.endsWith("/capabilities")) return Promise.resolve(jsonResponse({ capabilities: managedCapabilityWorkspace() }));
      if (url.endsWith("/operations")) return Promise.resolve(jsonResponse({ operations: operationsWithDeployedSketch([]) }));
      if (url.endsWith("/sites/apply-preview")) {
        if (options.deferred) return options.deferred;
        if (options.inspectionError) return Promise.resolve(new Response(JSON.stringify({ errors: ["Cannot inspect website files; check the proxy connection and review again."] }), { status: 400 }));
        const preview = webStaticApplyPreviewJob();
        preview.contentReview.state = options.state ?? "existing";
        return Promise.resolve(jsonResponse(preview));
      }
      if (url.endsWith("/static-web/sites") && init?.method === "POST") {
        if (options.applyError) return Promise.resolve(new Response(JSON.stringify({ errors: ["Website files changed after review. Review again."] }), { status: 400 }));
        return Promise.resolve(jsonResponse(webStaticApplyJob()));
      }
      return Promise.resolve(jsonResponse({}));
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await screen.findByText("ready");
    fireEvent.click(screen.getByRole("button", { name: "Capabilities" }));
    fireEvent.click(await screen.findByRole("button", { name: "Configure Static Web" }));
    const workflow = screen.getByRole("region", { name: "Static web service workflow" });
    fireEvent.click(within(workflow).getByRole("button", { name: "Add Site" }));
    return within(workflow).getByRole("region", { name: "Site Configuration" });
  }
  it("invalidates site edits and ignores an old in-flight review", async () => {
    let resolve!: (response: Response) => void;
    const deferred = new Promise<Response>((done) => { resolve = done; });
    const form = await openSite({ deferred });
    fireEvent.click(within(form).getByRole("button", { name: "Preview Web Apply" }));
    fireEvent.change(within(form).getByLabelText("Web site name"), { target: { value: "different-site" } });
    await act(async () => resolve(jsonResponse(webStaticApplyPreviewJob())));
    expect(within(form).queryByRole("group", { name: "Website content review" })).not.toBeInTheDocument();
    expect(within(form).getByRole("button", { name: "Apply Static Web" })).toBeDisabled();
  });
  it("shows empty-directory initialization without a destructive default", async () => {
    const form = await openSite({ state: "empty" });
    fireEvent.click(within(form).getByRole("button", { name: "Preview Web Apply" }));
    await within(form).findByText("Empty website directory");
    expect(within(form).queryByRole("radio")).not.toBeInTheDocument();
    expect(within(form).getByText(/starter page will be created/)).toBeInTheDocument();
    expect(within(form).getByRole("button", { name: "Apply Static Web" })).toBeEnabled();
  });
  it("blocks Apply after inspection errors rather than assuming empty", async () => {
    const form = await openSite({ inspectionError: true });
    fireEvent.click(within(form).getByRole("button", { name: "Preview Web Apply" }));
    await screen.findAllByText(/Cannot inspect website files/);
    expect(within(form).getByRole("button", { name: "Apply Static Web" })).toBeDisabled();
    expect(within(form).queryByText("Empty website directory")).not.toBeInTheDocument();
  });
  it("requires a new review after stale-content rejection", async () => {
    const form = await openSite({ applyError: true });
    fireEvent.click(within(form).getByRole("button", { name: "Preview Web Apply" }));
    await within(form).findByRole("radio", { name: "Preserve existing content" });
    fireEvent.click(within(form).getByRole("button", { name: "Apply Static Web" }));
    await screen.findAllByText(/Website files changed after review/);
    expect(within(form).getByRole("button", { name: "Apply Static Web" })).toBeDisabled();
  });
});
