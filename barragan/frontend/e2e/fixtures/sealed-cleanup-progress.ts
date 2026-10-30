/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { publishedTeardownFixture } from "./published-teardown-progress";

/** Reporting fixture only: opaque hashes stand in for backend-validated evidence. */
export function sealedCleanupFixture(status: "queued" | "running" | "failed" | "succeeded" = "running") {
  const base = publishedTeardownFixture();
  const engagementId = base.engagement.id;
  const coreJobId = base.core.id;
  const marker = { schema: "published-initial-failed-http-cleanup-v1", sha256: "a".repeat(64) };
  const terminal = status === "succeeded";
  const snapshotId = "example-sealed-cleanup-snapshot";
  const parent = {
    ...base.parent,
    id: "job-engagement-teardown-example",
    action: "engagement_comprehensive_teardown",
    status,
    input: {
      engagementId, coreJobId, publishedInitialCleanupAuthority: marker,
      scopeSnapshot: {
        engagementId, coreJobId, snapshotId,
        publishedInitialCleanupSeal: { ...marker, engagementId, coreJobId },
        confirmationPhrase: "teardown-example-fixture", chains: [],
        ownedProviderRecordIds: [], excludedUnmanagedProviderRecords: [],
        core: { jobId: coreJobId, workspace: "/example/core", proxyCount: 1 },
        publicVerificationTargets: [
          { id: "tcp:203.0.113.40:22", type: "tcp-forbidden", host: "203.0.113.40", port: 22, targetGroup: "core-public-management" },
          { id: "tcp:203.0.113.41:80", type: "tcp-forbidden", host: "203.0.113.41", port: 80, targetGroup: "former-public-listener" }
        ],
        inspector: { tracked: true, ownedProviderRecordIds: [], recordOwners: {}, verificationTargetCount: 2 }
      }
    },
    events: [
      { sequence: 1, level: "info", message: "engagement teardown queued", data: { snapshotId, publishedInitialCleanupAuthority: marker } },
      { sequence: 2, level: "info", message: terminal ? "engagement lifecycle reconciled" : "Example fixture: saved provider cleanup running",
        data: terminal ? { finalCleanupStatus: "verified_clean" } : status === "failed" ? { finalCleanupStatus: "cleanup_not_verified" } : {} }
    ],
    phase: terminal ? "complete" : "provider_destroy_apply",
    progress: { completed: terminal ? 9 : 2, total: 9 }
  };
  const lifecycle = terminal ? { state: "destroyed", label: "Destroyed", attentionRequired: false, terminal: true }
    : status === "failed" ? { state: "cleanup_required", label: "Cleanup required", attentionRequired: true, terminal: false }
    : { state: "tearing_down", label: "Tearing down", attentionRequired: false, terminal: false };
  const operations = {
    ...base.operations, lifecycle,
    teardownJob: { ...base.operations.teardownJob, id: parent.id, action: parent.action, status,
      recoveryState: terminal ? "complete" : status === "failed" ? "recoverable" : "in_progress", phase: parent.phase, progress: parent.progress }
  };
  return { ...base, parent, operations, engagement: { ...base.engagement, name: "Example fixture: sealed cleanup", lifecycle } };
}
