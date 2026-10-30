/* Copyright (c) 2026, Oracle and/or its affiliates. */
import producedSixParent from "./published-six-parent.json" with { type: "json" };
/** Offline Example fixture only. Never route this data into a live application. */
export function publishedTeardownFixture(options: {
  phase?: string; inputPhase?: string; completed?: number; status?: "queued" | "running" | "succeeded"; source?: "six" | "initial" | "unpublished-six";
} = {}) {
  const status = options.status ?? "queued";
  const terminal = status === "succeeded";
  const phase = terminal ? "complete" : options.phase ?? "core_destroy_apply";
  const inputPhase = terminal ? "lifecycle_reconciliation" : options.inputPhase ?? "plans_sealed";
  const completed = terminal ? 9 : options.completed ?? 4;
  const startedAt = terminal ? "2026-10-26T12:00:00Z" : new Date(Date.now() - 120_000).toISOString();
  const finishedAt = terminal ? "2026-10-26T12:02:00Z" : null;
  const engagementId = producedSixParent.input.engagementId;
  const coreJobId = producedSixParent.input.coreJobId;
  const corePlanId = producedSixParent.input.corePlanId;
  const parentId = producedSixParent.id;
  // Real asdict/checkpoint output, retaining all linked fixture identities.
  // Only transient local paths were normalized in the captured JSON.
  const sixSource = JSON.parse(JSON.stringify(producedSixParent.input.publishedSource));
  const initial = options.source === "initial";
  const order = initial ? ["digitalocean", "linode"] : producedSixParent.input.orderedProviders;
  const activeChild = terminal || ["destroy_plans", "lifecycle_reconciliation"].includes(phase) ? null :
    ["linode_absence", "digitalocean_absence"].includes(phase) ? {
      id: `job-provider-keyed-mixed-published-destroy-core-${phase.replace("_absence", "")}`,
      action: "provider_keyed_mixed_published_destroy_apply", status: "running",
      message: `Owned ${phase.replace("_absence", "")} cleanup is running`
    } : { id: "job-provider-keyed-mixed-core-destroy-apply-core", action: "provider_keyed_mixed_zero_apply_core_destroy_apply",
      status: "running", message: "Saved core plan execution is running" };
  const parent = {
    id: parentId, action: "provider_keyed_mixed_published_cleanup", status,
    targetType: "engagement", targetId: engagementId, requestedBy: "operator",
    input: { schema: "mixed-published-initial-cleanup-v1", engagementId,
      mutation: true, coreJobId, corePlanId, publishedParentId: initial ? "job-published" : producedSixParent.input.publishedParentId,
      ...(initial ? {} : { sourceKind: options.source === "unpublished-six" ? "unpublished-six-node-cleanup-v1" : producedSixParent.input.sourceKind }),
      publishedSource: initial ? { engagement_id: engagementId, core_job_id: coreJobId, core_plan_id: corePlanId,
        parent_job_id: "job-published", ordered_providers: ["digitalocean", "linode"],
        chain_ids: ["chain-do", "chain-linode"], provider_states: [{ provider: "digitalocean" }, { provider: "linode" }],
        host_rows: [{}, {}, {}, {}] } : sixSource, publishedSourceSha256: "a".repeat(64),
      orderedProviders: order, providerScopes: order.map((provider) => ({ provider })),
      providerScopeSha256: "c".repeat(64), reviewScope: { jobId: coreJobId, planId: corePlanId },
      reviewScopeSha256: "b".repeat(64), reviewSnapshotId: "snapshot-1", phase: inputPhase },
    dispatch: terminal ? { status: "succeeded", claimState: "unknown" as const, heartbeatAt: null, startedAt, finishedAt }
      : { status: "running", claimState: "live" as const, heartbeatAt: new Date(Date.now() - 5_000).toISOString(), startedAt, finishedAt },
    activeChild,
    activeChildState: activeChild === null ? "absent" as const : "exact" as const,
    phase, progress: { completed, total: 9 }, artifactRefs: [], events: [
      { sequence: 1, level: "info", message: "Example fixture: published mixed cleanup review queued", data: {} },
      ...(terminal ? [{ sequence: 2, level: "info", message: "published mixed teardown complete", data: { finalCleanupStatus: "verified_clean" } }] : [])]
  };
  const core = { id: coreJobId, action: "pilot_standard_rti_guarded_execute", status: "succeeded",
    targetType: "oci_compartment", targetId: "example-compartment", requestedBy: "operator",
    input: { engagementId, corePlanId }, artifactRefs: [],
    events: [{ sequence: 1, level: "info", message: "Historical deployment log: Example fixture", data: { finalCleanupStatus: "pending_operator_teardown" } }] };
  const lifecycle = status === "succeeded"
    ? { state: "destroyed", label: "Destroyed", attentionRequired: false, terminal: true }
    : { state: "tearing_down", label: "Tearing down", attentionRequired: false, terminal: false };
  const operations = { engagementId, housekeepingItems: "", lifecycle,
    activeJob: core, coreJob: core, mixedInitialJob: null,
    teardownSelection: { state: "exact" as const },
    teardownJob: { id: parentId, action: parent.action, status, recoveryState: status === "succeeded" ? "complete" : "in_progress",
      phase, progress: parent.progress, createdAt: "2026-10-26T11:00:00Z", finishedAt },
    healthSummary: { status: "unknown", hostCount: 0, source: "Example fixture", stale: false },
    coreInfrastructure: [], sketchInfrastructure: [], providerFindings: [], servicePlacements: [], outboundChannels: [], inboundChannels: [],
    sshConfig: { stanza: "", downloadName: "example-fixture" } };
  const engagement = { id: engagementId, name: "Example fixture: teardown progress", status: "active", owner: "operator",
    templateId: "small-dev-infra", activeRevision: "rev-example", lifecycle };
  return { parent, core, operations, engagement };
}
