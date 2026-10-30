/* Copyright (c) 2026, Oracle and/or its affiliates. */
export type AtcConfiguration = { operatorId: string; operatorName: string; port: number };
export type InferenceProxyConfiguration = { region: string; compartmentId: string; port: number };

export type InferenceProxyStatus = {
  status: "blocked" | "not_checked" | "checking" | "checked" | "failed";
  configuration: InferenceProxyConfiguration | null;
  bindingFingerprint: string | null;
  homebaseIdentity: { coreDeploymentId: string; instanceId: string } | null;
  observation: {
    checkedAt: string;
    localReady: boolean;
    discoveryStatus: string;
    lastRefreshAt: string | null;
    modelCount: number | null;
    errorCode: string | null;
    inferenceVerified: false;
  } | null;
  job: JobRunDetail | null;
  errors: string[];
};

export type HealthResponse = {
  service: string;
  status: string;
  database: {
    uriScheme: string;
    path: string;
    seedStatus: string;
  };
};

export type EngagementWorkspaceRecord = {
  engagementId: string;
  slug: string;
  path: string;
  status: string;
  profileId: string;
};

export type CertificateProfile = {
  engagementId: string;
  acmeEmail: string;
  defaultEnvironment: "staging" | "production";
  updatedAt: string;
};

export type CertificateVersion = {
  id: string;
  certificateId: string;
  sequence: number;
  status: string;
  acmeEnvironment: string;
  keyGeneration: number;
  issuer: string;
  serialNumber: string;
  fingerprintSha256: string;
  publicMetadata: Record<string, unknown>;
  paths: Record<string, unknown>;
  issuedAt: string;
  expiresAt: string;
  revokedAt: string;
  lastJobId: string;
  createdAt: string;
  updatedAt: string;
};

export type CertificateAsset = {
  id: string;
  name: string;
  source: "letsencrypt" | "self-signed" | "external";
  targetProxyId: string;
  identifiers: string[];
  primaryIdentifier: string;
  status: string;
  currentVersionId: string;
  lastJobId: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
  currentVersion?: CertificateVersion | null;
  versions: CertificateVersion[];
  bindings: Array<{ id: string; channelId: string; hostname: string; status: string }>;
  productionConfirmations: { issue: string; renew: string; reissue: string; revoke: string };
};

export type CertificateManagerWorkspace = {
  engagement: { id: string; name: string };
  profile: CertificateProfile;
  certificates: CertificateAsset[];
  proxies: Array<{ id: string; label: string; status: string }>;
  sources: CertificateAsset["source"][];
  maxIdentifiers: number;
};

export type CertificateBindingWorkspace = {
  channel: InboundChannelInput;
  certificate: CertificateAsset | null;
  binding: { id: string; certificateId: string; status: string } | null;
  candidates: CertificateAsset[];
  routeStatus: string;
  tlsStatus: string;
  job?: JobRunDetail | null;
};

export type TemplateSummary = {
  id: string;
  name: string;
  version: string;
  description: string;
  defaultNodeGroups: string[];
  supportedProviders: string[];
};

export type TemplateDetail = TemplateSummary & {
  parameters: Array<{
    name: string;
    label: string;
    kind: string;
    required: boolean;
    default: unknown;
    options: string[];
    description: string;
  }>;
  nodeGroups: Array<{
    role: string;
    provider: string;
    count: number;
    required: boolean;
    subnet: string | null;
    enabledByDefault: boolean;
  }>;
  serviceProfiles: Array<{
    id: string;
    name: string;
    placement: string;
    requiresIngressRoute: boolean;
    publishesEgressProfile: boolean;
    requiresReverseChannel: boolean;
  }>;
  providerConstraints: Record<string, unknown>;
  routeDefaults: Record<string, unknown>;
  reverseChannelDefaults: Record<string, unknown>;
};

export type TemplateValidation = {
  valid: boolean;
  errors: string[];
  normalized: Record<string, unknown>;
};

export type CapabilitySelectionRef = {
  hostClass: string;
  id: string;
};

export type EngagementCapabilityEntry = {
  id: string;
  name: string;
  description: string;
  hostClass: string;
  classification: "essential" | "default" | "optional" | "internal" | "unsupported" | string;
  resolution: "catalog" | "missing-manifest" | "missing-template-path" | string;
  executable: boolean;
  selected: boolean;
  locked: boolean;
  implementation: {
    type?: string;
    path?: string;
    role?: string;
    [key: string]: unknown;
  };
  operator: {
    visible?: boolean;
    selectable?: boolean;
    [key: string]: unknown;
  };
};

export type EngagementCapabilityWorkspace = {
  atc?: { configuration: AtcConfiguration };
  inferenceProxy?: { configuration: InferenceProxyConfiguration; accessStatus: "not_verified"; policyGuidance: { notes: string[]; documentationUrl: string } };
  workspace: {
    engagementId: string;
    slug: string;
    path: string;
    status: string;
    profileId: string;
    metadata: Record<string, unknown>;
  } | null;
  profileResolution: {
    source: { path: string; kind: string; warning: string };
    profile: { id: string; name: string; description: string; source: string };
    status: string;
    hostClasses: Record<string, Record<string, EngagementCapabilityEntry[]>>;
    summary: Record<string, number>;
    warnings: Array<Record<string, string>>;
    selection: {
      selectedDefaults: CapabilitySelectionRef[];
      deselectedDefaults: CapabilitySelectionRef[];
      selectedOptionals: CapabilitySelectionRef[];
      excludedCapabilities: CapabilitySelectionRef[];
    };
  };
  nativeState?: {
    staticWeb?: {
      claimed: boolean;
      claimingCount: number;
      claimingSiteIds: string[];
      selected: boolean;
      implied: boolean;
      reason: string;
    };
    backflips?: {
      configureRoute: "backflips";
      proxies: Array<{ proxyId: string; status: "Waiting" | "Configuring" | "Ready" | "Failed"; jobId: string }>;
    };
  };
  applyState: CapabilityApplyState;
  overrides: {
    selectedDefaults: CapabilitySelectionRef[];
    deselectedDefaults: CapabilitySelectionRef[];
    selectedOptionals: CapabilitySelectionRef[];
    excludedCapabilities: CapabilitySelectionRef[];
  };
  executionPolicy: {
    terraform: boolean;
    ansible: boolean;
    providerMutation: boolean;
    reason: string;
  };
};

export type EngagementCapabilitySelectionRequest = {
  atc?: AtcConfiguration;
  inferenceProxy?: InferenceProxyConfiguration;
  deselectedDefaults: CapabilitySelectionRef[];
  selectedOptionals?: CapabilitySelectionRef[];
};

export type CapabilityApplyStatus = "unsaved" | "saved_ready" | "applying" | "applied" | "blocked" | "partial" | "failed";

export type CapabilityApplyChild = {
  kind: "optional_roles" | "desktop";
  status: "pending" | "running" | "succeeded" | "failed" | "blocked" | "not_required";
  jobId: string;
  detail: string;
};

export type CapabilityApplyState = {
  status: CapabilityApplyStatus;
  selectionFingerprint: string;
  renderedInputFingerprint: string;
  preparedAt: string;
  startedAt: string;
  finishedAt: string;
  parentJobId: string;
  errors: string[];
  children: CapabilityApplyChild[];
};

export type CapabilityApplyResult = {
  status: CapabilityApplyStatus;
  applyState: CapabilityApplyState;
  job: JobRunDetail | null;
};

export type CapabilityLockRenderResponse = {
  workspace: EngagementCapabilityWorkspace["workspace"];
  capabilityLock: {
    path: string;
    relativePath: string;
    schema: string;
    status: string;
    profileId: string;
    summary: Record<string, number>;
    warnings: Array<Record<string, string>>;
    content: string;
  };
};

export type CapabilityReconciliationPlan = {
  selectedCount: number;
  executableCount: number;
  roleCount: number;
  rolesByHostClass: Record<string, Array<{ id: string; role: string }>>;
  targetHostClasses: string[];
  availableHostClasses: string[];
  skipped: Array<Record<string, string>>;
  warnings: Array<Record<string, string>>;
  errors: Array<Record<string, string>>;
  [key: string]: unknown;
};

export type CapabilityReconciliation = {
  status: string;
  plan: CapabilityReconciliationPlan | null;
  job: JobRunDetail | null;
  errors?: string[];
};

export type EngagementSummary = {
  id: string;
  name: string;
  status: string;
  owner: string;
  templateId: string | null;
  activeRevision: string | null;
  sketchStateSchema?: "split-v1" | "provider-keyed-v2";
  description: string;
  documentationUrl: string;
  jiraUrl: string;
  createdAt?: string;
  updatedAt?: string;
  lifecycle?: EngagementLifecycle;
  inputParameters?: Record<string, unknown>;
};

export type EngagementLifecycleState =
  | "not_deployed"
  | "deploying"
  | "active"
  | "tearing_down"
  | "cleanup_required"
  | "destroyed"
  | "unknown";

export type EngagementLifecycle = {
  state: EngagementLifecycleState;
  label: string;
  attentionRequired: boolean;
  terminal: boolean;
  administrativeStatus: string;
  evidence: Array<Record<string, string>>;
  evidenceFingerprint: string;
  reconciledAt: string | null;
};

export type EngagementDetail = EngagementSummary & {
  inputParameters: Record<string, unknown>;
};

export type TeamSshKey = {
  id: string;
  label: string;
  fingerprint: string;
  status: string;
  publicKey: string;
  createdAt: string;
  retiredAt: string | null;
};

export type TeamMember = {
  id: string;
  username: string;
  displayName: string;
  email: string;
  status: string;
  desiredUid?: number | null;
  defaultInfraGroups: string[];
  globalRoles: string[];
  sshKeys: TeamSshKey[];
  createdAt: string;
  updatedAt: string;
  deactivatedAt: string | null;
};

export type TeamWorkspace = {
  members: TeamMember[];
  supportedInfraGroups: string[];
  defaultInfraGroups: string[];
  supportedGlobalRoles?: string[];
  supportedAppPrivileges: string[];
};

export type TeamImportRecord = {
  status?: "active" | "deactivated" | null;
  sourceIndex: number;
  username: string;
  displayName: string;
  desiredUid?: number | null;
  defaultInfraGroups: string[];
  sshKeys: Array<{
    label: string;
    publicKey: string;
    fingerprint: string;
    sourceIndex: string;
  }>;
  errors: string[];
  action: "create" | "update" | "unchanged" | "invalid";
  memberId: string;
  changes: string[];
  keyAdditions: number;
  existingKeyCount: number;
};

export type TeamImportPreview = {
  format: string;
  fileName: string;
  summary: {
    creates: number;
    updates: number;
    unchanged: number;
    invalid: number;
    keyAdditions: number;
  };
  records: TeamImportRecord[];
  warnings: string[];
};

export type TeamImportRequest = {
  content: string;
  fileName?: string;
  format?: string;
};

export type TeamImportApplyResponse = {
  preview: TeamImportPreview;
  applied: {
    created: string[];
    updated: string[];
    unchanged: string[];
    skipped: Array<{ username: string; errors: string[] }>;
    keyAdditions: number;
  };
  team: TeamWorkspace;
};

export type EngagementTeamMembership = {
  id: string;
  engagementId: string;
  memberId: string;
  member: TeamMember;
  appPrivileges: string[];
  infraAccessEnabled: boolean;
  infraGroupsOverride: string[] | null;
  effectiveInfraGroups: string[];
  targetScope: string;
  targetHosts: string[];
  status: string;
  infrastructureState: string;
  applyJobId: string;
  createdAt: string;
  updatedAt: string;
  removedAt: string | null;
};

export type EngagementTeamWorkspace = {
  engagementId: string;
  memberships: EngagementTeamMembership[];
  availableMembers: TeamMember[];
  supportedInfraGroups: string[];
  supportedAppPrivileges: string[];
  defaultTargets: string[];
};

export type EngagementAccessPlan = {
  mode: string;
  liveApply: boolean;
  targetHosts: string[];
  sketchTargets: string[];
  sudoGroup: string;
  coreUsers: Array<{
    membershipId: string;
    memberId: string;
    username: string;
    displayName: string;
    infraGroups: string[];
    sshKeyFingerprints: string[];
    appPrivileges: string[];
    infrastructureState: string;
  }>;
  disabledUsers: Array<{
    membershipId: string;
    memberId: string;
    username: string;
    displayName: string;
    infraGroups: string[];
    sshKeyFingerprints: string[];
    appPrivileges: string[];
    infrastructureState: string;
  }>;
  warnings: string[];
  summary: string;
};

export type TeamMemberRequest = {
  username: string;
  displayName?: string;
  email?: string;
  desiredUid?: number | null;
  defaultInfraGroups?: string[];
  globalRoles?: string[];
};

export type EngagementTeamRequest = {
  memberId?: string;
  appPrivileges?: string[];
  infraAccessEnabled?: boolean;
  infraGroupsOverride?: string[] | null;
  inheritInfraGroups?: boolean;
  status?: string;
};

export type DashboardInventory = {
  generatedAt: string;
  summary: {
    templates: number;
    engagements: number;
    activeEngagements: number;
    jobRuns: number;
    activeInfrastructure: number;
    attention: number;
    destroyed: number;
    lastKnown: number;
    orphanCandidates: number;
    recentTeardowns?: number;
    recentArchives?: number;
  };
  engagementOverview?: {
    active: DashboardEngagementActivity[];
    recentlyEnded: DashboardEngagementActivity[];
    recentlyArchived: DashboardEngagementActivity[];
    windowDays: number;
  };
  systemHealth?: {
    api: DashboardHealthCheck;
    database: DashboardHealthCheck & {
      uriScheme?: string;
      path?: string;
      seedStatus?: string;
    };
    disk: DashboardHealthCheck & {
      path?: string;
      freeBytes?: number;
      totalBytes?: number;
      usedPercent?: number;
    };
    providers: DashboardHealthCheck & {
      orphanCandidates?: number;
    };
  };
  inventory: Array<{
    engagementId: string;
    engagementName: string;
    engagementStatus: string;
    lifecycleState: string;
    healthStatus: string;
    coreHostCount: number;
    activeCoreHostCount: number;
    sketchHostCount: number;
    activeSketchHostCount: number;
    outboundChannelCount: number;
    inboundChannelCount: number;
    providers: string[];
    regions: string[];
    lastCheckedAt: string | null;
    lastKnown: boolean;
    attention: boolean;
    detail: string;
  }>;
  orphanCandidates: DashboardOrphanCandidate[];
  providerDiscovery?: {
    status: "not_checked" | "disabled" | "checked" | "partial" | "failed";
    observedAt: string | null;
    cached: boolean;
    ageSeconds: number | null;
    detail: string;
    providers: Array<{
      provider: string;
      status: "disabled" | "checked" | "partial" | "unavailable" | "failed";
      observedAt: string | null;
      resourceCount: number;
      coverage: string[];
      detail: string;
    }>;
  };
  providerInventory?: Array<{
    provider: string;
    resourceType: string;
    resourceId: string;
    name: string;
    region: string;
    lifecycleState: string;
    engagementId: string;
    engagementName: string;
    source: string;
    classification: "recorded" | "barragan_orphan" | "unmanaged_rti" | "observation_only";
    barraganOwned: boolean;
    observedAt: string | null;
    actions: never[];
  }>;
  reconciliation: {
    status: string;
    detail: string;
  };
};

export type DashboardHealthCheck = {
  status: string;
  detail: string;
  checkedAt?: string | null;
};

export type DashboardEngagementActivity = {
  engagementId: string;
  engagementName: string;
  engagementStatus: string;
  lifecycleState: string;
  healthStatus: string;
  healthDetail: string;
  activeSince: string | null;
  activeDurationDays: number | null;
  activeDurationLabel: string;
  endedAt: string | null;
  archivedAt: string | null;
  providers: string[];
  regions: string[];
  lastCheckedAt: string | null;
};

export type DashboardOrphanCandidate = {
  candidateId: string;
  provider: string;
  resourceType: string;
  resourceId: string;
  name: string;
  region: string;
  lifecycleState: string;
  engagementId: string;
  engagementName: string;
  source: string;
  metadata?: Record<string, unknown>;
  publicIps?: string[];
  classification?: string;
  reason: string;
  actions: string[];
};

export type ProviderOrphanRecoveryAction = "track" | "mark_destroyed" | "tear_down";

export type ProviderOrphanRecoveryResponse = {
  candidate: DashboardOrphanCandidate;
  job: JobRunDetail;
  status: string;
  confirmationToken: string;
};

export type OperationsHealth = {
  status: string;
  source?: string;
  lastCheckedAt?: string | null;
  stale?: boolean;
  detail?: string;
};

export type TeardownWorkerProgress = {
  dispatch?: { status: string; claimState: "live" | "expired" | "unknown"; heartbeatAt: string | null; startedAt?: string | null; finishedAt?: string | null };
  activeChild?: { id: string; action: string; status: string; message: string } | null;
  activeChildState?: "exact" | "absent" | "ambiguous";
};

export type JobRunSummary = {
  id: string;
  action: string;
  status: string;
  createdAt: string;
  finishedAt: string | null;
  recoveryState?: "absent" | "in_progress" | "recoverable" | "complete" | "blocked";
  phase?: string;
  progress?: { completed: number; total: number };
  dispatch?: TeardownWorkerProgress["dispatch"];
  activeChild?: TeardownWorkerProgress["activeChild"];
  activeChildState?: TeardownWorkerProgress["activeChildState"];
};

export type EngagementOperationsOverview = {
  engagementId: string;
  lifecycle?: EngagementLifecycle;
  housekeepingItems: string;
  activeJob: JobRunSummary | null;
  coreJob?: JobRunSummary | null;
  mixedInitialJob?: JobRunSummary | null;
  teardownJob?: JobRunSummary | null;
  teardownSelection?: { state: "exact" | "absent" | "ambiguous" | "unavailable" };
  healthSummary: OperationsHealth & {
    hostCount: number;
    activeHostCount?: number;
  };
  coreInfrastructure: Array<{
    hostId?: string;
    logicalName?: string;
    expectedHostname?: string;
    hostname: string;
    role: string;
    status?: string;
    lifecycleState?: string;
    lastKnown?: boolean;
    publicIp: string;
    privateIp: string;
    region: string;
    compartment: string;
    services: string[];
    health: OperationsHealth;
  }>;
  sketchInfrastructure: Array<{
    chainId: string;
    componentId?: string;
    edgeId?: string;
    assignedProxyId?: string;
    hostname: string;
    provider: string;
    role: string;
    publicIp: string;
    region: string;
    proxy: string;
    status: string;
    health?: OperationsHealth;
    burned: boolean;
    burnedNote: string;
  }>;
  providerFindings?: DashboardOrphanCandidate[];
  servicePlacements?: Array<{
    hostId: string;
    hostRole: string;
    service: string;
    status: string;
    port: string;
    detail: string;
    serviceId?: string;
    serviceType?: string;
    domain?: string;
    siteName?: string;
    protocol?: string;
    transport?: string;
    purpose?: string;
    scriptPath?: string;
    tags?: string[];
    notes?: string;
    validationProfile?: InboundValidationProfile;
  }>;
  outboundChannels: Array<{
    channelId?: string;
    chainId: string;
    edgeIndex?: string;
    edgeCount?: string;
    proxy: string;
    middle: string;
    edge: string;
    port: string;
    region: string;
    provider: string;
    domain: string;
    purpose: string;
    status: string;
    profileName?: string;
    publicationPath?: string;
    validation?: {
      origin?: string;
      command?: string[];
      shellDisplay?: string;
      expectedPublicIp?: string;
      status?: string;
      checkedAt?: string;
      lastCheckedAt?: string;
      detail?: string;
    };
    artifactTargets?: Record<string, string>;
  }>;
  inboundChannels: Array<{
    channelId: string;
    chainId?: string;
    edgeComponentId?: string;
    middleComponentId?: string;
    domain: string;
    protocol: string;
    mode?: string;
    externalPort: string;
    relayPort?: string;
    middleRelayPort?: string;
    proxyRelayPort?: string;
    edge: string;
    middle: string;
    proxy: string;
    terminatesOn: string;
    service: string;
    serviceId?: string;
    serviceType?: string;
    internalPort: string;
    backendPort?: string;
    purpose: string;
    status: string;
    validationProfile?: InboundValidationProfile;
    validation?: {
      profileType?: string;
      profileLabel?: string;
      listenerOrigin?: string;
      listenerCommand?: string[];
      listenerShellDisplay?: string;
      validationScope?: string;
      externalIngressVerified?: boolean;
      externalIngressCheckedAt?: string;
      externalIngressDetail?: string;
      ingressEndpoint?: string;
      probeOrigin?: string;
      probeCommand?: string[];
      probeShellDisplay?: string;
      expectedMarker?: string;
      expectedResponse?: string;
      observedResponse?: string;
      status?: string;
      checkedAt?: string;
      lastCheckedAt?: string;
      detail?: string;
    };
    artifactTargets?: Record<string, string>;
  }>;
  sshConfig: {
    stanza: string;
    downloadName: string;
  };
};

export type SketchChainRecord = {
  chainId: string;
  engagementId: string;
  assignedProxy: string;
  middleProvider: string;
  middleRegion: string;
  middleSize: string;
  edgeProvider: string;
  edgeRegion: string;
  edgeSize: string;
  edgeCount: number;
  edges: Array<{ id: string; provider: string; region: string; size: string }>;
  status: string;
  burned: boolean;
  burnedNote: string;
  deployJobId: string;
  teardownJobId: string;
  terraformWorkingDirectory: string;
  nodes: Array<Record<string, unknown>>;
  createdAt: string;
  updatedAt: string;
};

export type KeyedEdgeAppendPlanReview = {
  available: boolean;
  status: string;
  applyAvailable?: boolean;
  applyRequested?: boolean;
  failedReviewDiscardState?: "" | "waiting" | "ready";
  unscheduledReviewCancelState?: "" | "waiting" | "ready";
  failedApplyRecoveryState?: "" | "waiting" | "ready";
  publicationRecoveryState?: "" | "waiting" | "ready";
  parentJobId?: string;
  planJobId?: string;
  planStatus?: string;
  newEdgeAddress?: string;
  planSha256?: string;
};

export type MixedAppendEdgeChoices = {
  digitalocean: { selectedChainId: string; edgeRegion: string; edgeSize: string };
  linode: { selectedChainId: string; edgeRegion: string; edgeType: string };
};

export type MixedAppendPlanReview = {
  retryAvailable?: boolean;
  retryChoices?: MixedAppendEdgeChoices;
  available: boolean;
  status: string;
  parentJobId?: string;
  planJobId?: string;
  planStatus?: string;
  reviewSha256?: string;
  applyAvailable?: boolean;
  proofResumeAvailable?: boolean;
  applyStage?: string;
  attention?: boolean;
  reviewSummary?: {
    schema: "mixed-append-pair-review-summary-v1";
    providerOrder: string[];
    plans: Array<{
      provider: string;
      selectedChainId: string;
      edgeRegion: string;
      edgeSizeOrType: string;
      newEdgeAddress: string;
      savedPlanSha256: string;
    }>;
    outcome: string;
  };
};

export type CreateSketchChainRequest = {
  assignedProxy: string;
  middleProvider: string;
  middleRegion: string;
  middleSize: string;
  edgeProvider: string;
  edgeRegion: string;
  edgeSize: string;
  edgeCount: number;
  edges?: Array<{ id: string; provider: string; region: string; size: string }>;
};

export type UpdateSketchChainRequest = Partial<CreateSketchChainRequest> & {
  burned?: boolean;
  burnedNote?: string;
};

export type OutboundChannelInput = {
  channelId?: string;
  chainId?: string;
  edgeIndex?: string;
  edgeCount?: string;
  proxy?: string;
  middle?: string;
  edge?: string;
  port?: string;
  region?: string;
  provider?: string;
  domain?: string;
  purpose?: string;
  status?: string;
  profileName?: string;
  publicationPath?: string;
  validation?: {
    origin?: string;
    command?: string[];
    shellDisplay?: string;
    expectedPublicIp?: string;
    status?: string;
    checkedAt?: string;
    lastCheckedAt?: string;
    detail?: string;
  };
  artifactTargets?: Record<string, string>;
};

export type InboundIngressAssessmentCheck = {
  id: string;
  scope: string;
  label: string;
  status: "allowed" | "managed" | "blocked" | "unknown" | string;
  protocol: string;
  port: number;
  host: string;
  detail: string;
  source?: string;
  correctiveAction?: string;
};

export type InboundIngressAssessment = {
  status: "allowed" | "blocked" | string;
  applyAllowed: boolean;
  protocol: string;
  externalPort: number;
  relayPort?: number;
  middleRelayPort?: number;
  proxyRelayPort: number;
  terminationPort: number;
  checks: InboundIngressAssessmentCheck[];
  blockedChecks: string[];
  blockingReasons: string[];
  summary: string;
};

export type InboundValidationProfileType = "temporary-listener" | "tcp-connect" | "tcp-send-receive" | "http" | "udp-send-receive" | "manual";

export type InboundValidationProfile = {
  type: InboundValidationProfileType;
  label?: string;
  requestText?: string;
  expectedResponse?: string;
};

export type InboundChannelCertificatePrerequisite = {
  id: string;
  label: string;
  status: string;
  detail: string;
};

export type InboundChannelCertificatePrerequisites = {
  status: string;
  ready: boolean;
  summary: string;
  checkedAt: string;
  edgePublicIp?: string;
  domainAssetId?: string;
  challengeType?: "dns-01" | string;
  dnsZone?: string;
  challengeChannelId?: string;
  checks: InboundChannelCertificatePrerequisite[];
};

export type InboundChannelCertificate = {
  type?: "letsencrypt" | "self-signed" | string;
  status?: string;
  domain?: string;
  acmeEmail?: string;
  acmeEnvironment?: string;
  challengeType?: "dns-01" | string;
  storageModel?: string;
  activationStatus?: string;
  cleanupRequired?: boolean;
  issuedAt?: string;
  expiresAt?: string;
  revokedAt?: string;
  renewedAt?: string;
  lastJobId?: string;
  challengeChannelId?: string;
  detail?: string;
  paths?: {
    liveDir?: string;
    fullchain?: string;
    privkey?: string;
    cert?: string;
    chain?: string;
  };
  prerequisites?: Partial<InboundChannelCertificatePrerequisites>;
};

export type InboundChannelCertificateWorkspace = {
  channel: InboundChannelInput;
  certificate: InboundChannelCertificate;
  prerequisites: InboundChannelCertificatePrerequisites;
};

export type InboundChannelCertificateRequest = {
  certificateType: "letsencrypt" | "self-signed";
  acmeEmail?: string;
  acmeEnvironment?: "staging" | "production";
  productionConfirmation?: string;
  requestedBy?: string;
};

export type InboundChannelCertificateActionResult = {
  job: JobRunDetail;
  certificate?: InboundChannelCertificate;
  prerequisites?: InboundChannelCertificatePrerequisites;
  channel?: InboundChannelInput;
  status: string;
};

export type InboundRequestHeaderGateTokenAction = "keep" | "generate" | "provide";

export type InboundRequestHeaderGateWorkspace = {
  channel: InboundChannelInput;
  edgePublicIp: string;
  gate: {
    configured: boolean;
    enabled: boolean;
    headerName: string;
    token: string;
    status: string;
    maxRequestBodyMb: number;
  };
  authorizedRequest: {
    method: "GET";
    curl: string;
  };
  backendPolicy?: {
    capabilityId: string;
    authorizationManaged: boolean;
    maxRequestBodyMb: number;
  } | null;
  pending?: {
    state: "running" | "retry-required";
    jobId: string;
    message: string;
  };
  job?: JobRunDetail;
};

export type InboundRequestHeaderGateRequest = {
  enabled: boolean;
  headerName: string;
  tokenAction: InboundRequestHeaderGateTokenAction;
  token?: string;
  maxRequestBodyMb: number;
};

export type InboundChannelInput = {
  channelId?: string;
  chainId?: string;
  edgeComponentId?: string;
  middleComponentId?: string;
  batchId?: string;
  domain?: string;
  protocol?: string;
  mode?: string;
  externalPort?: string;
  relayPort?: string;
  middleRelayPort?: string;
  proxyRelayPort?: string;
  edge?: string;
  middle?: string;
  proxy?: string;
  terminatesOn?: string;
  service?: string;
  serviceId?: string;
  serviceType?: string;
  internalPort?: string;
  backendPort?: string;
  purpose?: string;
  status?: string;
  validationProfile?: InboundValidationProfile;
    validation?: {
      profileType?: string;
      profileLabel?: string;
      listenerOrigin?: string;
      listenerCommand?: string[];
      listenerShellDisplay?: string;
      validationScope?: string;
      externalIngressVerified?: boolean;
      ingressEndpoint?: string;
      probeOrigin?: string;
      probeCommand?: string[];
      probeShellDisplay?: string;
    expectedMarker?: string;
    expectedResponse?: string;
    observedResponse?: string;
    status?: string;
    checkedAt?: string;
    lastCheckedAt?: string;
    detail?: string;
  };
  artifactTargets?: Record<string, string>;
  ingressAssessment?: InboundIngressAssessment;
  certificate?: InboundChannelCertificate;
  certificateSupport?: {
    role?: string;
    parentChannelId?: string;
    purpose?: string;
    dependency?: string;
    status?: string;
  };
};

export type InboundManagedRuntime = {
  routeId: string;
  channelId: string;
  mode: string;
  routingOwner: { kind: "shared-web-ingress" | "dedicated-stream"; label: string; managedBy: string };
  selectedPath: { chainId?: string | null; edge?: string | null; middle?: string | null; proxy?: string | null };
  externalListener: { host?: string | null; port?: string | null; protocol: string };
  termination: { host?: string | null; port?: string | null; service?: string | null };
  site?: {
    domain?: string | null;
    serviceName: string;
    containerPort: string;
    backend: { kind: string; host?: string | null; port?: string | null };
  } | null;
  certificate?: Record<string, string | number | boolean> | null;
  managedArtifacts: Array<{ scope: string; path: string }>;
  artifactStatus: string;
  validation: Record<string, string | number | boolean>;
  latestJob?: { id: string; action: string; status: string; startedAt?: string | null; finishedAt?: string | null } | null;
  failClosedDefault?: { target: string; detail: string };
  readOnly: true;
};

export type InboundChannelCreateRequest = {
  chainId: string;
  edge: string;
  edgeComponentId: string;
  protocol: string;
  mode?: string;
  externalPort: string;
  relayPort?: string;
  middleRelayPort?: string;
  proxyRelayPort?: string;
  terminatesOn: string;
  internalPort: string;
  service?: string;
  serviceId?: string;
  serviceType?: string;
  domain?: string;
  purpose?: string;
  validationProfile?: InboundValidationProfile;
};

export type UpdateEngagementOperationsRequest = {
  housekeepingItems?: string;
  outboundChannels?: OutboundChannelInput[];
  inboundChannels?: InboundChannelInput[];
};

export type CreateEngagementRequest = {
  name?: string;
  owner: string;
  sketchStateSchema?: "split-v1" | "provider-keyed-v2";
  description?: string;
  documentationUrl?: string;
  jiraUrl?: string;
  templateId?: string;
  inputParameters?: Record<string, unknown>;
};

export type UpdateEngagementRequest = {
  name: string;
  owner: string;
  description: string;
  documentationUrl: string;
  jiraUrl: string;
};

export type ConfigureEngagementInfrastructureRequest = {
  templateId: string;
  inputParameters: Record<string, unknown>;
};

export type CredentialSummary = {
  id: string;
  provider: string;
  alias: string;
  status: string;
  description: string;
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
};

export type CreateCredentialRequest = {
  provider: string;
  alias: string;
  description?: string;
  secret: string;
};

export type RotateCredentialRequest = {
  description?: string;
  secret: string;
};

export type CredentialValidation = {
  credential: CredentialSummary;
  decryptable: boolean;
};

export type DomainRiskStatus = "clear" | "burned" | "quarantined" | "cooldown" | string;

export type DomainAssignment = {
  id: number | null;
  domainId: string;
  engagementId: string;
  engagementName: string;
  purpose: string;
  purposeTags?: string[];
  status: string;
  notes: string;
  assignedAt: string;
  releasedAt: string | null;
};

export type DomainSummary = {
  id: string;
  domainName: string;
  registrar: string;
  registration: {
    createdAt: string;
    expiresAt: string;
    autoRenew: boolean;
  };
  healthRisk: {
    status: DomainRiskStatus;
    flags: string[];
    cooldownUntil: string;
    assignableOverride: boolean;
  };
  providerStatus: string;
  notes: string;
  catalogState: string;
  lastSyncedAt: string | null;
  bucket: keyof DomainGroups | string;
  engagement: {
    id: string;
    name: string;
  } | null;
  purpose: string;
  purposeTags?: string[];
  dnsSummary?: {
    recordCount: number;
    recordsPreview: DomainHostRecord[];
    source: string;
    syncJobId: string;
    fetchedAt: string;
  };
};

export type DomainDetail = DomainSummary & {
  assignments: DomainAssignment[];
};

export type DomainGroups = {
  currently_being_used: DomainSummary[];
  waiting_to_be_used: DomainSummary[];
  used_in_past_engagements: DomainSummary[];
};

export type DomainHostRecord = {
  name: string;
  type: string;
  address: string;
  ttl: string;
  mxPref?: string;
};

export type DomainHostsSnapshot = {
  domainId: string;
  domainName: string;
  provider: string;
  source: string;
  syncJobId: string;
  fetchedAt: string;
  hosts: DomainHostRecord[];
  readOnly: boolean;
};

export type DomainConfirmationRequired = {
  required: boolean;
  token: string;
  reasons: string[];
};

export type DomainAssignRequest = {
  engagementId: string;
  purpose?: string;
  purposeTags?: string[];
  notes?: string;
  assignedBy?: string;
  confirmationToken?: string;
};

export type DomainSyncResponse = {
  job: JobRunDetail;
  domainsSynced: number;
  hostSnapshots: number;
};

export type EngagementDnsRecord = DomainHostRecord;

export type EngagementDnsDomain = DomainSummary & {
  dns: DomainHostsSnapshot & {
    currentFingerprint: string;
  };
};

export type EngagementDnsEdgeTarget = {
  id: string;
  label: string;
  chainId: string;
  hostname: string;
  provider: string;
  publicIp: string;
  region: string;
  proxy: string;
  status: string;
};

export type EngagementDnsDiff = {
  added: EngagementDnsRecord[];
  updated: Array<{ before: EngagementDnsRecord; after: EngagementDnsRecord }>;
  removed: EngagementDnsRecord[];
  unchanged: EngagementDnsRecord[];
};

export type EngagementDnsWorkspace = {
  engagementId: string;
  domains: EngagementDnsDomain[];
  edgeTargets: EngagementDnsEdgeTarget[];
  supportedRecordTypes: string[];
  defaultTtl: number;
  notice: string;
};

export type EngagementDnsPreview = {
  domain: DomainSummary;
  currentRecords: EngagementDnsRecord[];
  desiredRecords: EngagementDnsRecord[];
  diff: EngagementDnsDiff;
  currentFingerprint: string;
};

export type EngagementDnsApplyResponse = {
  job: JobRunDetail;
  status: string;
};

export type SketchProviderPreflight = {
  provider: string;
  ready: boolean;
  catalogSource: string;
  checkedRegion: string;
  checkedSize: string;
  errors: string[];
  warnings: string[];
  mutation: boolean;
  opsecBoundary: {
    directSketchAccessFromAppHost: boolean;
    middleAccess: string;
    edgeAccess: string;
  };
};

export type JobRunSummary = {
  id: string;
  action: string;
  status: string;
  target: string;
  createdAt: string;
};

export type JobRunPagination = {
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
};

export type JobEvent = {
  sequence: number;
  level: string;
  message: string;
  data: Record<string, unknown>;
};

export type JobRunDetail = {
  id: string;
  action: string;
  status: string;
  targetType: string;
  targetId: string;
  requestedBy: string;
  input: Record<string, unknown>;
  artifactRefs: string[];
  events: JobEvent[];
  phase?: string;
  progress?: { completed: number; total: number };
  dispatch?: TeardownWorkerProgress["dispatch"];
  activeChild?: TeardownWorkerProgress["activeChild"];
  activeChildState?: TeardownWorkerProgress["activeChildState"];
};

export type EngagementTeardownScopeItem = {
  id: string;
  label: string;
  items: Array<Record<string, unknown>>;
};

export type EngagementTeardownPreview = {
  snapshotId: string;
  engagementId: string;
  engagementName: string;
  confirmationPhrase: string;
  parentJobId: string | null;
  orderedScope: EngagementTeardownScopeItem[];
};

export type OutboundChannelApplyWorkspace = {
  status: string;
  mutation: boolean;
  inventory: {
    target: string;
    sha256: string;
    byteCount: number;
  };
  playbook: {
    target: string;
    sha256: string;
    byteCount: number;
  };
  manifest: {
    target: string;
    sha256: string;
    byteCount: number;
  };
};

export type OutboundChannelApplyPreview = {
  job: JobRunDetail;
  workspace: OutboundChannelApplyWorkspace;
};

export type OutboundChannelActionResult = {
  job: JobRunDetail;
  status?: string;
};

export type OutboundAutoConfigFailure = {
  status: "Auto Configuration Failed";
  errors: string[];
};

export type SketchChainDeployResult = {
  chain: SketchChainRecord;
  job: JobRunDetail;
  outboundApply?: OutboundChannelActionResult | OutboundAutoConfigFailure;
  outboundValidation?: OutboundChannelActionResult;
};

export type SketchChainRefreshResult = {
  sketchChain: SketchChainRecord;
  outboundApply?: OutboundChannelActionResult | OutboundAutoConfigFailure;
  outboundValidation?: OutboundChannelActionResult;
};

export type InboundChannelApplyPreview = {
  job: JobRunDetail;
  workspace: {
    status: string;
    mutation: boolean;
    channel: InboundChannelInput;
    artifacts: Record<string, unknown>;
    ingressAssessment?: InboundIngressAssessment;
  };
};

export type InboundChannelActionResult = {
  job: JobRunDetail;
  status?: string;
};

export type InboundChannelWorkflowResult = InboundChannelActionResult & {
  channel: InboundChannelInput;
};

export type InboundChannelBatchPreview = {
  submissionId: string;
  previewFingerprint: string;
  channels: InboundChannelInput[];
  applyOrder: string[];
  warnings: string[];
  status: string;
  summary: string;
};

export type InboundChannelBatchResult = {
  batchId: string;
  channels: InboundChannelInput[];
  job: JobRunDetail;
};

export type InboundChannelPrepareResult = InboundChannelWorkflowResult;

export type InspectorSettings = {
  engagementId: string;
  enabled: boolean;
  provider: string;
  region: string;
  size: string;
  mode: "once" | "regular" | "continuous";
  scheduleWeekdays: string[];
  scheduleTimeUtc: string;
  checkFamilies: string[];
  forbiddenTcpPorts: string[];
  portScanProfiles: Record<string, unknown>[];
  currentHost: Record<string, unknown>;
  idleRetentionUntil: string;
  lastScheduledSlot: string;
  lastMutationJobInspected: string;
  configured: boolean;
  confirmationToken: string;
  defaults: {
    provider: string;
    regions: Record<string, string>;
    sizes: Record<string, string>;
    forbiddenTcpPorts: string[];
    mode: "once" | "regular" | "continuous";
    scheduleWeekdays: string[];
    scheduleTimeUtc: string;
    checkFamilies: string[];
  };
  createdAt?: string;
  updatedAt?: string;
};

export type ObserverSettings = InspectorSettings;

export type InspectorCleanupResource = {
  provider: string;
  resourceType: string;
  resourceId: string;
  name: string;
  region?: string;
  publicIp?: string;
  status?: string;
  tag?: string;
  associatedResources?: InspectorCleanupResource[];
};

export type InspectorCleanupPreview = {
  engagementId: string;
  engagementName: string;
  confirmationToken: string;
  canDestroy: boolean;
  blockers: string[];
  hosts: InspectorCleanupResource[];
  resourceCount: number;
  scope: Record<string, boolean>;
};

export type InspectorSettingsRequest = {
  enabled: boolean;
  provider: string;
  region: string;
  size: string;
  mode: "once" | "regular" | "continuous";
  scheduleWeekdays: string[];
  scheduleTimeUtc: string;
  checkFamilies: string[];
  forbiddenTcpPorts: string[];
  portScanProfiles: Record<string, unknown>[];
};

export type ObserverSettingsRequest = InspectorSettingsRequest;

export type InspectionRun = {
  id: string;
  engagementId: string;
  jobId: string;
  triggerType: string;
  mode: string;
  status: string;
  provider: string;
  region: string;
  host: Record<string, unknown>;
  targets: Record<string, unknown>;
  evidence: Record<string, unknown>;
  findings: Record<string, unknown>[];
  createdAt: string;
  startedAt?: string | null;
  finishedAt?: string | null;
};

export type ObserverCheckResult = {
  job: JobRunDetail;
  status?: string;
  inspection?: InspectionRun;
};

export type InspectorReadinessResult = {
  required: boolean;
  ready: boolean;
  status: "not_required" | "running" | "ready" | "failed";
  reused?: boolean;
  inspectorHost?: Record<string, unknown>;
  job: JobRunDetail | null;
  errors?: string[];
};

export type BackflipsServiceApplyWorkspace = {
  status: string;
  mutation: boolean;
  inventory: {
    target: string;
    content: string;
  };
  playbook: {
    target: string;
    content: string;
  };
  manifest: {
    target: string;
    content: string;
  };
};

export type BackflipsServiceApplyPreview = {
  job: JobRunDetail;
  workspace: BackflipsServiceApplyWorkspace;
};

export type BackflipsServiceActionResult = {
  job: JobRunDetail;
  status?: string;
};

export type LegacyHomebaseRoleServiceCatalogEntry = {
  slug: string;
  name: string;
  targetHost: string;
  role: string;
  detail: string;
  confirmation: string;
  package?: string;
  disableNote?: string;
};

export type LegacyHomebaseRoleServiceApplyWorkspace = BackflipsServiceApplyWorkspace;

export type LegacyHomebaseRoleServiceApplyPreview = {
  job: JobRunDetail;
  workspace: LegacyHomebaseRoleServiceApplyWorkspace;
  service: Record<string, unknown>;
};

export type DesktopServiceApp = LegacyHomebaseRoleServiceCatalogEntry;

export type DesktopServiceDesiredApp = {
  slug: string;
  enabled: boolean;
};

export type DesktopServiceCatalog = {
  service: {
    serviceId: string;
    serviceType: string;
    name: string;
    targetHost: string;
    confirmation: string;
  };
  apps: DesktopServiceApp[];
};

export type DesktopServiceActionResult = {
  job: JobRunDetail;
  status?: string;
  servicePlacements: Array<Record<string, unknown>>;
};

export type OpsecNetworkRestrictionsConfiguration = {
  enabled: boolean;
  destinations: string[];
  notes: string;
  purpose: string;
  managedComment?: string;
};

export type OpsecNetworkRestrictionsRequest = {
  enabled: boolean;
  destinations: string[];
  notes?: string;
  purpose?: string;
};

export type OpsecNetworkRestrictionsWorkspace = {
  service: EngagementService;
  configuration: OpsecNetworkRestrictionsConfiguration;
};

export type OpsecNetworkRestrictionsActionResult = OpsecNetworkRestrictionsWorkspace & {
  job: JobRunDetail;
  status?: string;
};

export type LegacyHomebaseRoleServiceActionResult = {
  job: JobRunDetail;
  status?: string;
  service: Record<string, unknown>;
};

export type EngagementService = {
  engagementId: string;
  serviceId: string;
  serviceType: string;
  name: string;
  proxyId: string;
  status: string;
  config: {
    siteName?: string;
    domain?: string;
    internalPort?: number;
    contentPath?: string;
    siteConfigPath?: string;
    composePath?: string;
    targetHost?: string;
    protocol?: string;
    transport?: string;
    scriptPath?: string;
    purpose?: string;
    tags?: string[];
    notes?: string;
    validationProfile?: InboundValidationProfile;
    [key: string]: unknown;
  };
  applyJobId: string;
  createdAt: string;
  updatedAt: string;
};

export type WebStaticServiceRequest = {
  proxyId: string;
  siteName: string;
  domain: string;
  internalPort: string;
  indexHtml?: string;
  contentAction?: "preserve" | "restore-starter";
  contentReviewJobId?: string;
  contentFiles?: Array<{
    path: string;
    content?: string;
    contentBase64?: string;
    encoding?: "text" | "base64";
  }>;
};

export type GenericServiceRequest = {
  serviceId?: string;
  name: string;
  targetHost: string;
  internalPort: string;
  protocol: "tcp" | "udp" | "http" | "https" | string;
  scriptPath?: string;
  purpose?: string;
  tags?: string[];
  notes?: string;
  validationProfile?: InboundValidationProfile;
};

export type GenericServiceActionResult = {
  service: EngagementService;
};

export type WebStaticServiceApplyWorkspace = {
  status: string;
  mutation: boolean;
  inventory: {
    target: string;
    content: string;
  };
  playbook: {
    target: string;
    content: string;
  };
  manifest: {
    target: string;
    content: string;
  };
  artifacts: Array<{
    target: string;
    content: string;
  }>;
};

export type WebStaticServiceApplyPreview = {
  contentReview?: {
    reviewJobId: string;
    state: "empty" | "existing";
    fingerprint: string;
    defaultAction: "preserve";
    allowedActions: Array<"preserve" | "restore-starter">;
    message: string;
  };
  job: JobRunDetail;
  workspace: WebStaticServiceApplyWorkspace;
  service: EngagementService;
  capabilityPrerequisite?: {
    ready: boolean;
    workspacePrepared: boolean;
    selected: boolean;
    willSelectOnApply: boolean;
    reason: string;
  };
};

export type WebStaticServiceRemovePreview = {
  job: JobRunDetail;
  workspace: WebStaticServiceApplyWorkspace;
  service: EngagementService;
  confirmationToken: string;
};

export type WebStaticServiceActionResult = {
  job: JobRunDetail;
  service: EngagementService;
  status?: string;
};

export type DeploymentRevision = {
  id: string;
  engagementId: string;
  revisionNumber: number;
  status: string;
  templateId: string;
  inputParameters: Record<string, unknown>;
  resolvedTopology: Record<string, unknown>;
  runIntent: Array<Record<string, unknown>>;
  validationGates: Array<{
    id: string;
    label: string;
    status: string;
    severity: string;
    message: string;
  }>;
};

export type RenderResult = {
  renderId: string;
  revisionId: string;
  root: string;
  artifacts: Array<{
    path: string;
    sha256: string;
  }>;
};

export type RenderRevisionRequest = {
  renderDestination?: string;
  renderJobId?: string;
};

export type PlanOnlyDeployment = {
  revision: DeploymentRevision;
  providerPlan: Record<string, unknown>;
  terraformIntent: Record<string, unknown>;
  ansibleIntent: Record<string, unknown>;
  accessPlan: Record<string, unknown>;
  renderResult: RenderResult | null;
  terraformFiles?: Array<{
    path: string;
    language: "hcl" | "json";
    source: string;
  }>;
  events: JobEvent[];
};

export type CoreInfrastructurePlanStatus =
  | "initial"
  | "preparing"
  | "ready"
  | "no_changes"
  | "succeeded"
  | "failed"
  | "outdated"
  | "invalidated"
  | "applying"
  | "applied"
  | "used"
  | "reconciliation_required";

export type CoreInfrastructurePlanAction = "add" | "update" | "replace" | "remove" | "read" | "output" | "no_op";

export type CoreInfrastructureComputeProfile = {
  id: string;
  name: string;
  fingerprint: string;
  bootVolumeSizeGiB: number;
  roles: Array<{
    role: "homebase" | "proxy" | "elk";
    label: string;
    nodeCount: number;
    shape: string;
    ocpus: number;
    memoryGiB: number;
  }>;
};

export type CoreInfrastructurePlan = {
  id: string;
  engagementId: string;
  revisionId: string;
  keyedDeployEligible?: boolean;
  status: CoreInfrastructurePlanStatus;
  stage: string;
  counts: Record<Exclude<CoreInfrastructurePlanAction, "no_op">, number>;
  resourceChanges: Array<{
    action: CoreInfrastructurePlanAction;
    address: string;
    type: string;
    provider: string;
    displayName: string;
    group: string;
    region?: string | null;
  }>;
  target: {
    name: string;
    region: string;
  };
  reviewedConfiguration: {
    templateId: string;
    templateName: string;
    core: {
      homebases: number;
      proxies: number;
      elkEnabled: boolean;
    };
    target: {
      name: string;
      region: string;
    };
    sshSourceCidrs: string[];
    computeProfile?: CoreInfrastructureComputeProfile | null;
    sketchAuthorization?: {
      kind: "bounded-post-core";
      provider: "digitalocean";
      providerConnectionId: string;
      image: string;
      source: {
        revision: string;
        templateSha256: string;
        providerLock: { path: string; sha256: string; digitaloceanVersion: string };
      };
      chains: Array<{
        id: string;
        fingerprint: string;
        assignedProxy: string;
        middle: { provider: "digitalocean"; region: string; size: string };
        edges: Array<{ id: string; provider: "digitalocean"; region: string; size: string }>;
      }>;
      firewall: {
        publicTcpPorts: string[];
        publicUdpPorts: string[];
        publicIpv6Allowed: boolean;
        managementSsh: { port: number; sourceRule: "selected-proxy-public-ipv4-32"; proxyNames: string[] };
        peerIngress: { protocols: string[]; portRange: string; sourceRule: "all-created-middle-and-edge-public-ipv4-32" };
        outboundIpv4: Array<{ protocol: string; portRange?: string; destination: string }>;
      };
      fingerprint: string;
    } | {
      kind: "bounded-mixed-post-core-v1";
      providerScopes: Array<{
        provider: "linode" | "digitalocean";
        providerConnectionId: string;
        image: string;
        chain: {
          id: string;
          assignedProxy: string;
          middle: { provider: string; region: string; size: string };
          edges: Array<{ id: string; provider: string; region: string; size: string }>;
        };
        firewall: {
          publicTcpPorts: string[];
          publicUdpPorts: string[];
          publicIpv6Allowed: boolean;
        };
      }>;
      fingerprint: string;
    };
  };
  postCoreScope: {
    sketchStateSchema?: "split-v1" | "provider-keyed-v2";
    chainCount: number;
    middleCount: number;
    edgeCount: number;
    providers: string[];
    chains: Array<{
      id: string;
      intentId?: string;
      assignedProxy: string;
      middle: { provider: string; region: string };
      edges: Array<{ id: string; provider: string; region: string }>;
    }>;
  };
  preparedAt: string | null;
  ageWarningAt?: string | null;
  sshSourceCidrs: string[];
  inputFingerprint: string;
  computeProfile?: CoreInfrastructureComputeProfile | null;
  sanitizedTextKind: "summary" | "terraform_plan";
  sanitizedText: string;
  terraformFiles: Array<{
    path: string;
    language: "hcl" | "json";
    content: string;
  }>;
  error?: string | null;
};

export type PrepareCoreInfrastructurePlanRequest = {
  revisionId: string;
  sshSourceCidrs: string[];
};

export type CommandResolution = {
  binaryName: string;
  command: string | null;
  source: string | null;
  overrideVariables: string[];
  ok: boolean;
  error: string | null;
};

export type DisposableDeploymentReadiness = {
  target: {
    name: string;
    compartmentId: string;
    parentCompartmentId: string;
    region: string;
    auth: string;
    mutation: boolean;
    classification?: "testing" | "production";
  };
  availableTargets?: Array<{
    name: string;
    compartmentId: string;
    parentCompartmentId: string;
    region: string;
    auth: string;
    mutation: boolean;
    classification?: "testing" | "production";
  }>;
  workspace: string;
  mutationScope: string;
  expectedInstanceDisplayName?: string;
  expectedInstanceDisplayNames?: string[];
  expectedVcnDisplayName?: string;
  topology?: {
    template: string;
    engagementName?: string;
    vcnCidr: string;
    subnets: Array<{
      role: string;
      cidr: string;
      privateIp: string;
    }>;
    nodes: Array<{
      role: string;
      displayName: string;
      privateIp: string;
    }>;
    deferred: string[];
  };
  confirmationToken: string;
  deploymentModes?: {
    default: string;
    supported: string[];
  };
  cleanupAcknowledgement: {
    field: string;
    required: boolean;
    label: string;
  };
  commands: {
    planned: string[][];
    cleanupVerification: string[][];
  };
  commandResolution: {
    oci: CommandResolution;
    terraform: CommandResolution;
    ansible?: CommandResolution;
    ansiblePlaybook?: CommandResolution;
  };
  sshKeyConfiguration?: {
    publicKeyEnv: string;
    privateKeyEnv: string;
    sourceCidrEnv?: string;
    sourceCidrsEnv?: string;
    publicKeyConfigured: boolean;
    privateKeyConfigured: boolean;
    sourceCidrConfigured?: boolean;
    sourceCidrsConfigured?: boolean;
  };
  sshIngress?: {
    sourceCidrEnv: string;
    sourceCidrsEnv?: string;
    sourceCidrConfigured: boolean;
    sourceCidrsConfigured?: boolean;
    defaultSourceCidrs?: string[];
    allowsPublicInternet: boolean;
    publicInternetCidr: string;
    requirement: string;
  };
  sshReadiness?: {
    bounded: boolean;
    module: string;
    timeoutSeconds: number;
    sleepSeconds: number;
    connectTimeoutSeconds: number;
    knownHostsPath: string;
    hostKeyPolicy: string;
  };
  guardrails: {
    allowedCompartment: string;
    allowedCompartmentId: string;
    allowedRegion: string;
    noTouchCompartments: string[];
    mutationBoundary: string;
    harmlessAnsibleActions?: string[];
    disallowedResourceFamilies: string[];
  };
};

export type DisposableDeploymentResult = {
  ok: boolean;
  deploymentMode?: string;
  mutation: boolean;
  mutationStatus: string;
  ansibleStatus?: string;
  finalCleanupStatus: string;
  workspaceDir?: string;
  target?: Record<string, unknown>;
  preflight?: {
    ok: boolean;
  };
  cleanupVerification?: {
    ok: boolean;
    remainingCount: number | null;
    error: string | null;
    checks?: Array<{
      resource: string;
      ok: boolean;
      remainingCount: number | null;
      error: string | null;
    }>;
  } | null;
  commandsRun?: Array<{
    command: string[];
    cwd: string | null;
    returncode: number;
    stdout: string;
    stderr: string;
    ok: boolean;
  }>;
};

export type RunDisposableDeploymentRequest = {
  engagementId?: string | null;
  confirmMutation: string;
  confirmDestroyCleanup?: boolean;
  deploymentMode?: string;
  recreateCore?: boolean;
  recreateConfirmation?: string;
  sshSourceCidr?: string;
  sshSourceCidrs?: string[];
  workspaceDir?: string;
};

export type StartLinodeSketchRunRequest = {
  confirmMutation: string;
  engagementId: string;
  coreJobId: string;
  chainId: string;
  assignedProxy: string;
  middleRegion: string;
  middleSize: string;
  middleCredentialAlias?: string;
  edgeRegion: string;
  edgeSize: string;
  edgeCount?: number;
  edgeCredentialAlias?: string;
};

export type ProviderCatalogOption = {
  id: string;
  label: string;
  available: boolean;
  allowed?: boolean;
};

export type ProviderCatalogSize = ProviderCatalogOption & {
  vcpus: number | null;
  memoryMb: number | null;
  diskGb: number | null;
  priceMonthly: number | null;
  regions: string[];
};

export type SketchProviderCatalog = {
  provider: string;
  regions: ProviderCatalogOption[];
  sizes: ProviderCatalogSize[];
  defaults: {
    region: string;
    size: string;
  };
  source: string;
  cachedAt: string;
  expiresAt: string;
  warnings: string[];
  regionPolicy?: {
    allowedRegions: string[];
    includeBlocked: boolean;
  };
};

export type ProviderRegionPolicy = {
  provider: string;
  allowedRegions: string[];
  createdAt: string;
  updatedAt: string;
};

export type SketchSshKey = {
  engagementId: string;
  privateKeyName: string;
  publicKeyName: string;
  fingerprint: string;
  retiredKeys?: Array<{
    privateKeyName: string;
    publicKeyName: string;
    fingerprint: string;
    status: string;
    reason: string;
    retiredAt: string;
  }>;
  createdAt: string;
  updatedAt: string;
};

export type SketchSshKeyRotationPlan = {
  engagementId: string;
  status: string;
  mutation: boolean;
  currentKey: SketchSshKey | null;
  confirmation: string;
  requiresRepair: boolean;
  affectedChains: Array<Record<string, unknown>>;
  steps: Array<Record<string, unknown>>;
  opsecBoundary: Record<string, unknown>;
  previousFingerprint?: string;
};

export type SketchSshKeyRemovalPlan = {
  engagementId: string;
  status: string;
  mutation: boolean;
  currentKey: SketchSshKey | null;
  confirmation: string;
  requiresTeardown: boolean;
  blockers: Array<Record<string, unknown>>;
  steps: Array<Record<string, unknown>>;
  opsecBoundary: Record<string, unknown>;
  removedFingerprint?: string;
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";
const CSRF_STORAGE_KEY = "barragan.csrf-token";

export type AuthenticatedUser = {
  id: string;
  username: string;
  displayName: string;
  roles: string[];
};

export type AuthSession = {
  authRequired: boolean;
  authenticated: boolean;
  user: AuthenticatedUser | null;
  mustChangePassword: boolean;
  csrfToken?: string;
};

function storedCsrfToken(): string {
  return typeof window === "undefined" ? "" : window.localStorage.getItem(CSRF_STORAGE_KEY) ?? "";
}

export function rememberCsrfToken(token: string): void {
  if (typeof window === "undefined") return;
  if (token) window.localStorage.setItem(CSRF_STORAGE_KEY, token);
  else window.localStorage.removeItem(CSRF_STORAGE_KEY);
}

function mutationHeaders(): Record<string, string> {
  const csrfToken = storedCsrfToken();
  return {
    "Content-Type": "application/json",
    ...(csrfToken ? { "X-Barragan-CSRF": csrfToken } : {})
  };
}

export class BarraganApiError extends Error {
  status: number;
  body: unknown;

  constructor(status: number, message: string, body: unknown = null) {
    super(message);
    this.name = "BarraganApiError";
    this.status = status;
    this.body = body;
  }
}

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`;
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(apiUrl(path));
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.json() as Promise<T>;
}

async function postJson<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "POST",
    headers: mutationHeaders(),
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.json() as Promise<T>;
}

async function patchJson<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "PATCH",
    headers: mutationHeaders(),
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.json() as Promise<T>;
}

async function putJson<T>(path: string, body: unknown = {}): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "PUT",
    headers: mutationHeaders(),
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.json() as Promise<T>;
}

async function deleteJson<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method: "DELETE",
    headers: mutationHeaders(),
    ...(body === undefined
      ? {}
      : {
          body: JSON.stringify(body)
        })
  });
  if (!response.ok) {
    throw await apiError(response);
  }
  return response.json() as Promise<T>;
}

async function apiError(response: Response): Promise<BarraganApiError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  const message =
    typeof body === "object" && body !== null && "error" in body
      ? String((body as { error?: unknown }).error)
      : `Barragan API request failed: ${response.status}`;
  return new BarraganApiError(response.status, message, body);
}

export const apiClient = {
  health: () => getJson<HealthResponse>("/api/health"),
  authSession: async () => {
    const session = await getJson<AuthSession>("/api/auth/session");
    if (session.csrfToken) rememberCsrfToken(session.csrfToken);
    return session;
  },
  login: async (username: string, password: string) => {
    const session = await postJson<AuthSession>("/api/auth/login", { username, password });
    if (session.csrfToken) rememberCsrfToken(session.csrfToken);
    return session;
  },
  changePassword: async (currentPassword: string, newPassword: string) => {
    const session = await postJson<AuthSession>("/api/auth/password", { currentPassword, newPassword });
    if (session.csrfToken) rememberCsrfToken(session.csrfToken);
    return session;
  },
  logout: async () => {
    try {
      return await postJson<{ authenticated: false }>("/api/auth/logout");
    } finally {
      rememberCsrfToken("");
    }
  },
  logoutAll: async () => {
    try {
      return await postJson<{ authenticated: false }>("/api/auth/logout-all");
    } finally {
      rememberCsrfToken("");
    }
  },
  dashboard: (options: { live?: boolean } = {}) =>
    getJson<{ dashboard: DashboardInventory }>(`/api/dashboard${options.live ? "?live=1" : ""}`),
  recoverProviderOrphan: (body: {
    candidateId: string;
    action: ProviderOrphanRecoveryAction;
    requestedBy?: string;
    mutation?: boolean;
    confirmation?: string;
  }) => postJson<ProviderOrphanRecoveryResponse>("/api/dashboard/orphan-candidates/actions", body),
  templates: () => getJson<{ templates: TemplateSummary[] }>("/api/templates"),
  template: (templateId: string) => getJson<{ template: TemplateDetail }>(`/api/templates/${templateId}`),
  validateTemplate: (templateId: string, body: Record<string, unknown>) =>
    postJson<{ validation: TemplateValidation }>(`/api/templates/${templateId}/validate`, body),
  credentials: (provider?: string) => {
    const query = provider ? `?provider=${encodeURIComponent(provider)}` : "";
    return getJson<{ credentials: CredentialSummary[] }>(`/api/credentials${query}`);
  },
  createCredential: (body: CreateCredentialRequest) => postJson<{ credential: CredentialSummary }>("/api/credentials", body),
  validateCredential: (credentialId: string) =>
    postJson<{ validation: CredentialValidation }>(`/api/credentials/${credentialId}/validate`),
  setDefaultCredential: (credentialId: string) =>
    postJson<{ credential: CredentialSummary }>(`/api/credentials/${credentialId}/default`),
  rotateCredential: (credentialId: string, body: RotateCredentialRequest) =>
    patchJson<{ credential: CredentialSummary }>(`/api/credentials/${credentialId}`, body),
  deleteCredential: (credentialId: string) => deleteJson<{ credential: CredentialSummary }>(`/api/credentials/${credentialId}`),
  team: () => getJson<TeamWorkspace>("/api/team"),
  createTeamMember: (body: TeamMemberRequest) => postJson<{ member: TeamMember }>("/api/team", body),
  updateTeamMember: (memberId: string, body: Partial<TeamMemberRequest> & { status?: string }) =>
    patchJson<{ member: TeamMember }>(`/api/team/${memberId}`, body),
  deactivateTeamMember: (memberId: string) => postJson<{ member: TeamMember }>(`/api/team/${memberId}/deactivate`),
  addTeamMemberSshKey: (memberId: string, body: { label?: string; publicKey: string }) =>
    postJson<{ member: TeamMember; sshKey: TeamSshKey }>(`/api/team/${memberId}/ssh-keys`, body),
  updateTeamMemberSshKey: (memberId: string, keyId: string, body: { label?: string; publicKey?: string }) =>
    patchJson<{ member: TeamMember; sshKey: TeamSshKey }>(`/api/team/${memberId}/ssh-keys/${keyId}`, body),
  retireTeamMemberSshKey: (memberId: string, keyId: string) =>
    deleteJson<{ member: TeamMember; sshKey: TeamSshKey }>(`/api/team/${memberId}/ssh-keys/${keyId}`),
  previewTeamImport: (body: TeamImportRequest) => postJson<{ preview: TeamImportPreview }>("/api/team/import/preview", body),
  applyTeamImport: (body: TeamImportRequest) => postJson<TeamImportApplyResponse>("/api/team/import/apply", body),
  domains: () => getJson<{ domains: DomainGroups }>("/api/domains"),
  domainPurposes: () => getJson<{ purposes: string[] }>("/api/domains/purposes"),
  syncNamecheapDomains: (body: { includeHosts?: boolean; requestedBy?: string; credentialAlias?: string } = {}) =>
    postJson<DomainSyncResponse>("/api/domains/sync/namecheap", body),
  domainHosts: (domainId: string) => getJson<{ hosts: DomainHostsSnapshot }>(`/api/domains/${domainId}/hosts`),
  assignDomain: (domainId: string, body: DomainAssignRequest) =>
    postJson<{ domain: DomainDetail; assignment: DomainAssignment }>(`/api/domains/${domainId}/assign`, body),
  releaseDomain: (domainId: string, body: { releasedBy?: string } = {}) =>
    postJson<{ domain: DomainDetail; releasedAssignments: DomainAssignment[] }>(`/api/domains/${domainId}/release`, body),
  updateDomainAssignment: (domainId: string, body: { purpose?: string; purposeTags?: string[] }) =>
    patchJson<{ domain: DomainDetail; assignments: DomainAssignment[] }>(`/api/domains/${domainId}/assignment`, body),
  updateDomainCatalogState: (domainId: string, body: { catalogState: string }) =>
    patchJson<{ domain: DomainDetail }>(`/api/domains/${domainId}/catalog-state`, body),
  updateDomainRisk: (domainId: string, body: { riskStatus: string; riskFlags?: string[]; cooldownUntil?: string; assignableOverride?: boolean; notes?: string }) =>
    patchJson<{ domain: DomainDetail }>(`/api/domains/${domainId}/risk`, body),
  engagements: () => getJson<{ engagements: EngagementSummary[] }>("/api/engagements"),
  allEngagements: () => getJson<{ engagements: EngagementSummary[] }>("/api/engagements?scope=all"),
  createEngagement: (body: CreateEngagementRequest) => postJson<{ engagement: EngagementDetail }>("/api/engagements", body),
  engagement: (engagementId: string) => getJson<{ engagement: EngagementDetail }>(`/api/engagements/${engagementId}`),
  reconcileEngagementLifecycle: (engagementId: string) =>
    postJson<{ reconciliation: { previous: EngagementLifecycle | null; current: EngagementLifecycle; changed: boolean } }>(
      `/api/engagements/${engagementId}/lifecycle/reconcile`,
      {}
    ),
  updateEngagement: (engagementId: string, body: UpdateEngagementRequest) =>
    patchJson<{ engagement: EngagementDetail }>(`/api/engagements/${engagementId}`, body),
  engagementWorkspace: (engagementId: string) =>
    getJson<{ workspace: EngagementWorkspaceRecord | null }>(`/api/engagements/${engagementId}/workspace`),
  prepareEngagementWorkspace: (engagementId: string) =>
    postJson<{ workspace: EngagementWorkspaceRecord; created: boolean }>(`/api/engagements/${engagementId}/workspace`),
  engagementCapabilities: (engagementId: string) =>
    getJson<{ capabilities: EngagementCapabilityWorkspace }>(`/api/engagements/${engagementId}/capabilities`),
  inferenceProxyStatus: (engagementId: string) =>
    getJson<{ inferenceProxyStatus: InferenceProxyStatus }>(`/api/engagements/${engagementId}/capabilities/inference-proxy/status`),
  checkInferenceProxyStatus: (engagementId: string, bindingFingerprint: string) =>
    postJson<{ inferenceProxyStatus: InferenceProxyStatus }>(`/api/engagements/${engagementId}/capabilities/inference-proxy/status`, { bindingFingerprint }),
  updateEngagementCapabilities: (engagementId: string, body: EngagementCapabilitySelectionRequest) =>
    patchJson<{ capabilities: EngagementCapabilityWorkspace }>(`/api/engagements/${engagementId}/capabilities`, body),
  applyEngagementCapabilities: (engagementId: string) =>
    postJson<{ capabilityApply: CapabilityApplyResult }>(`/api/engagements/${engagementId}/capabilities/apply`, {}),
  renderEngagementCapabilityLock: (engagementId: string) =>
    postJson<{ render: CapabilityLockRenderResponse }>(`/api/engagements/${engagementId}/workspace/capability-lock`),
  engagementCapabilityReconciliation: (engagementId: string) =>
    getJson<{ reconciliation: CapabilityReconciliation }>(`/api/engagements/${engagementId}/capabilities/reconciliation`),
  reconcileEngagementCapabilities: (engagementId: string) =>
    postJson<{ reconciliation: CapabilityReconciliation }>(`/api/engagements/${engagementId}/capabilities/reconciliation`, {}),
  engagementOperations: (engagementId: string) =>
    getJson<{ operations: EngagementOperationsOverview }>(`/api/engagements/${engagementId}/operations`),
  engagementTeam: (engagementId: string) => getJson<EngagementTeamWorkspace>(`/api/engagements/${engagementId}/team`),
  enrollEngagementTeamMember: (engagementId: string, body: EngagementTeamRequest) =>
    postJson<EngagementTeamWorkspace & { membership: EngagementTeamMembership }>(`/api/engagements/${engagementId}/team`, body),
  updateEngagementTeamMembership: (engagementId: string, membershipId: string, body: EngagementTeamRequest) =>
    patchJson<EngagementTeamWorkspace & { membership: EngagementTeamMembership }>(`/api/engagements/${engagementId}/team/${membershipId}`, body),
  removeEngagementTeamMembership: (engagementId: string, membershipId: string) =>
    deleteJson<EngagementTeamWorkspace & { membership: EngagementTeamMembership }>(`/api/engagements/${engagementId}/team/${membershipId}`),
  engagementAccessPlan: (engagementId: string) =>
    postJson<{ plan: EngagementAccessPlan }>(`/api/engagements/${engagementId}/team/access-plan`),
  engagementAccessApply: (engagementId: string, body: { requestedBy?: string } = {}) =>
    postJson<{ job: JobRunDetail; plan: EngagementAccessPlan; status: string }>(`/api/engagements/${engagementId}/team/access-apply`, body),
  engagementDomains: (engagementId: string) => getJson<{ domains: DomainSummary[] }>(`/api/engagements/${engagementId}/domains`),
  engagementDns: (engagementId: string) => getJson<{ dns: EngagementDnsWorkspace }>(`/api/engagements/${engagementId}/dns`),
  certificateManager: (engagementId: string) =>
    getJson<{ certificateManager: CertificateManagerWorkspace }>(`/api/engagements/${engagementId}/certificates`),
  updateCertificateProfile: (engagementId: string, body: { acmeEmail: string; defaultEnvironment: "staging" | "production" }) =>
    patchJson<{ profile: CertificateProfile }>(`/api/engagements/${engagementId}/certificate-profile`, body),
  createCertificate: (engagementId: string, body: { name: string; source: CertificateAsset["source"]; targetProxyId: string; identifiers: string[]; notes?: string; certificatePem?: string }) =>
    postJson<{ certificate: CertificateAsset }>(`/api/engagements/${engagementId}/certificates`, body),
  updateCertificate: (engagementId: string, certificateId: string, body: { notes: string }) =>
    patchJson<{ certificate: CertificateAsset }>(`/api/engagements/${engagementId}/certificates/${certificateId}`, body),
  certificateLifecycle: (engagementId: string, certificateId: string, action: "issue" | "renew" | "reissue" | "revoke", body: Record<string, string> = {}) =>
    postJson<{ certificate: CertificateAsset; job: JobRunDetail; status: string }>(`/api/engagements/${engagementId}/certificates/${certificateId}/${action}`, { requestedBy: "operator", ...body }),
  retireCertificate: (engagementId: string, certificateId: string) =>
    postJson<{ certificate: CertificateAsset }>(`/api/engagements/${engagementId}/certificates/${certificateId}/retire`, {}),
  replaceExternalCertificate: (engagementId: string, certificateId: string, certificatePem: string) =>
    postJson<{ certificate: CertificateAsset }>(`/api/engagements/${engagementId}/certificates/${certificateId}/external-replacement`, { certificatePem }),
  previewEngagementDns: (engagementId: string, body: { domainId: string; records: EngagementDnsRecord[]; requestedBy?: string }) =>
    postJson<{ preview: EngagementDnsPreview }>(`/api/engagements/${engagementId}/dns/preview`, body),
  applyEngagementDns: (engagementId: string, body: { domainId: string; records: EngagementDnsRecord[]; currentFingerprint: string; requestedBy?: string }) =>
    postJson<EngagementDnsApplyResponse>(`/api/engagements/${engagementId}/dns/apply`, body),
  inspectorSettings: (engagementId: string) =>
    getJson<{ settings: InspectorSettings }>(`/api/engagements/${engagementId}/inspector-settings`),
  updateInspectorSettings: (engagementId: string, body: InspectorSettingsRequest) =>
    patchJson<{ settings: InspectorSettings }>(`/api/engagements/${engagementId}/inspector-settings`, body),
  runInspection: (engagementId: string, triggerType: "manual" | "scheduled" | "mutation" = "manual") =>
    postJson<ObserverCheckResult>(`/api/engagements/${engagementId}/inspections`, { triggerType, requestedBy: "operator" }),
  ensureInspectorReadiness: (engagementId: string) =>
    postJson<{ readiness: InspectorReadinessResult }>(`/api/engagements/${engagementId}/inspector-readiness`, { requestedBy: "operator" }),
  previewInspectorCleanup: (engagementId: string) =>
    postJson<{ preview: InspectorCleanupPreview }>(`/api/engagements/${engagementId}/inspector-cleanup-preview`, {}),
  cleanupInspector: (engagementId: string, confirmation: string) =>
    postJson<{ job: JobRunDetail; status: string }>(`/api/engagements/${engagementId}/inspector-cleanup`, { confirmation, requestedBy: "operator" }),
  inspections: (engagementId: string) =>
    getJson<{ inspections: InspectionRun[] }>(`/api/engagements/${engagementId}/inspections`),
  observerSettings: (engagementId: string) =>
    getJson<{ settings: ObserverSettings }>(`/api/engagements/${engagementId}/observer-settings`),
  updateObserverSettings: (engagementId: string, body: ObserverSettingsRequest) =>
    patchJson<{ settings: ObserverSettings }>(`/api/engagements/${engagementId}/observer-settings`, body),
  runObserverCheck: (engagementId: string, confirmation: string) =>
    postJson<ObserverCheckResult>(`/api/engagements/${engagementId}/observer-checks`, { confirmation, requestedBy: "operator" }),
  updateEngagementOperations: (engagementId: string, body: UpdateEngagementOperationsRequest) =>
    patchJson<{ operations: EngagementOperationsOverview }>(`/api/engagements/${engagementId}/operations`, body),
  applyPreviewOutboundChannel: (engagementId: string, chainId: string) =>
    postJson<OutboundChannelApplyPreview>(`/api/engagements/${engagementId}/outbound-channels/${chainId}/apply-preview`),
  applyOutboundChannel: (engagementId: string, chainId: string, confirmation: string) =>
    postJson<OutboundChannelActionResult>(`/api/engagements/${engagementId}/outbound-channels/${chainId}/apply`, {
      confirmation
    }),
  validateOutboundChannel: (engagementId: string, chainId: string, confirmation: string) =>
    postJson<OutboundChannelActionResult>(`/api/engagements/${engagementId}/outbound-channels/${chainId}/validate`, {
      confirmation
    }),
  previewInboundChannelApply: (engagementId: string, channelId: string) =>
    postJson<InboundChannelApplyPreview>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/apply-preview`),
  createInboundChannel: (engagementId: string, body: InboundChannelCreateRequest) =>
    postJson<InboundChannelWorkflowResult>(`/api/engagements/${engagementId}/inbound-channels`, body),
  previewInboundChannelBatch: (engagementId: string, submissionId: string, channels: InboundChannelCreateRequest[]) =>
    postJson<InboundChannelBatchPreview>(`/api/engagements/${engagementId}/inbound-channel-batches/preview`, { submissionId, channels }),
  prepareInboundChannel: (engagementId: string, submissionId: string, previewFingerprint: string, channel: InboundChannelCreateRequest) =>
    postJson<InboundChannelPrepareResult>(`/api/engagements/${engagementId}/inbound-channels/prepare`, { submissionId, previewFingerprint, channel }),
  createInboundChannelBatch: (engagementId: string, submissionId: string, previewFingerprint: string, channels: InboundChannelCreateRequest[]) =>
    postJson<InboundChannelBatchResult>(`/api/engagements/${engagementId}/inbound-channel-batches`, { submissionId, previewFingerprint, channels }),
  retryInboundChannelBatch: (engagementId: string, batchId: string) =>
    postJson<InboundChannelBatchResult>(`/api/engagements/${engagementId}/inbound-channel-batches/${batchId}/retry`, {}),
  latestInboundChannelBatch: (engagementId: string) =>
    getJson<{ job: JobRunDetail | null }>(`/api/engagements/${engagementId}/inbound-channel-batches/latest`),
  applyInboundChannel: (engagementId: string, channelId: string, confirmation: string) =>
    postJson<InboundChannelActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/apply`, {
      confirmation
    }),
  validateInboundChannel: (engagementId: string, channelId: string, confirmation: string) =>
    postJson<InboundChannelActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/validate`, {
      confirmation
    }),
  removeInboundChannel: (engagementId: string, channelId: string, confirmation: string) =>
    deleteJson<InboundChannelActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}`, {
      confirmation
    }),
  recoverInboundChannel: (engagementId: string, channelId: string) =>
    postJson<InboundChannelWorkflowResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/recover`),
  inboundManagedRuntime: (engagementId: string, channelId: string) =>
    getJson<InboundManagedRuntime>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/managed-runtime`),
  inboundChannelRequestHeaderGate: (engagementId: string, channelId: string) =>
    getJson<InboundRequestHeaderGateWorkspace>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/request-header-gate`),
  updateInboundChannelRequestHeaderGate: (engagementId: string, channelId: string, body: InboundRequestHeaderGateRequest) =>
    putJson<InboundRequestHeaderGateWorkspace>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/request-header-gate`, body),
  inboundChannelCertificate: (engagementId: string, channelId: string) =>
    getJson<InboundChannelCertificateWorkspace>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate`),
  inboundChannelCertificateBinding: (engagementId: string, channelId: string) =>
    getJson<CertificateBindingWorkspace>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate-binding`),
  bindInboundChannelCertificate: (engagementId: string, channelId: string, certificateId: string) =>
    patchJson<CertificateBindingWorkspace>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate-binding`, { certificateId }),
  unbindInboundChannelCertificate: (engagementId: string, channelId: string) =>
    deleteJson<CertificateBindingWorkspace>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate-binding`),
  inboundChannelCertificatePrerequisites: (engagementId: string, channelId: string) =>
    getJson<{ channel: InboundChannelInput; prerequisites: InboundChannelCertificatePrerequisites }>(
      `/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate/prerequisites`
    ),
  // Compatibility endpoint for pre-DNS-01 clients; it performs no mutation.
  configureInboundChannelHttp01: (engagementId: string, channelId: string) =>
    postJson<InboundChannelCertificateActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate/challenge-channel`, {
      requestedBy: "operator"
    }),
  issueInboundChannelCertificate: (engagementId: string, channelId: string, body: InboundChannelCertificateRequest) =>
    postJson<InboundChannelCertificateActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate/issue`, body),
  renewInboundChannelCertificate: (engagementId: string, channelId: string, body: InboundChannelCertificateRequest) =>
    postJson<InboundChannelCertificateActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate/renew`, body),
  revokeInboundChannelCertificate: (engagementId: string, channelId: string) =>
    postJson<InboundChannelCertificateActionResult>(`/api/engagements/${engagementId}/inbound-channels/${channelId}/certificate/revoke`, {
      requestedBy: "operator"
    }),
  previewBackflipsServiceApply: (engagementId: string, proxyId: string) =>
    postJson<BackflipsServiceApplyPreview>(`/api/engagements/${engagementId}/capabilities/backflips/apply-preview`, {
      proxyId
    }),
  applyBackflipsService: (engagementId: string, proxyId: string, confirmation: string) =>
    postJson<BackflipsServiceActionResult>(`/api/engagements/${engagementId}/capabilities/backflips/apply`, {
      proxyId,
      confirmation
    }),
  legacyHomebaseRoleServices: (engagementId: string) =>
    getJson<{ services: LegacyHomebaseRoleServiceCatalogEntry[] }>(`/api/engagements/${engagementId}/services/legacy-homebase-roles`),
  previewLegacyHomebaseRoleServiceApply: (engagementId: string, roleSlug: string) =>
    postJson<LegacyHomebaseRoleServiceApplyPreview>(`/api/engagements/${engagementId}/services/legacy-homebase-roles/${roleSlug}/apply-preview`, {}),
  applyLegacyHomebaseRoleService: (engagementId: string, roleSlug: string, confirmation: string) =>
    postJson<LegacyHomebaseRoleServiceActionResult>(`/api/engagements/${engagementId}/services/legacy-homebase-roles/${roleSlug}/apply`, {
      confirmation
    }),
  desktopService: (engagementId: string) =>
    getJson<DesktopServiceCatalog>(`/api/engagements/${engagementId}/capabilities/desktop`),
  applyDesktopCapabilities: (engagementId: string) =>
    postJson<DesktopServiceActionResult>(`/api/engagements/${engagementId}/capabilities/desktop/apply`, {}),
  opsecNetworkRestrictions: (engagementId: string) =>
    getJson<OpsecNetworkRestrictionsWorkspace>(`/api/engagements/${engagementId}/capabilities/opsec-network-restrictions`),
  applyOpsecNetworkRestrictions: (engagementId: string, body: OpsecNetworkRestrictionsRequest) =>
    postJson<OpsecNetworkRestrictionsActionResult>(`/api/engagements/${engagementId}/capabilities/opsec-network-restrictions/apply`, body),
  engagementServices: (engagementId: string) =>
    getJson<{ services: EngagementService[] }>(`/api/engagements/${engagementId}/services`),
  previewWebStaticServiceApply: (engagementId: string, body: WebStaticServiceRequest) =>
    postJson<WebStaticServiceApplyPreview>(`/api/engagements/${engagementId}/capabilities/static-web/sites/apply-preview`, body),
  applyWebStaticService: (engagementId: string, body: WebStaticServiceRequest) =>
    postJson<WebStaticServiceActionResult>(`/api/engagements/${engagementId}/capabilities/static-web/sites`, body),
  previewWebStaticServiceRemove: (engagementId: string, serviceId: string) =>
    postJson<WebStaticServiceRemovePreview>(`/api/engagements/${engagementId}/capabilities/static-web/sites/${serviceId}/remove-preview`, {}),
  removeWebStaticService: (engagementId: string, serviceId: string, confirmation: string) =>
    deleteJson<WebStaticServiceActionResult>(`/api/engagements/${engagementId}/capabilities/static-web/sites/${serviceId}`, {
      confirmation
    }),
  createGenericService: (engagementId: string, body: GenericServiceRequest) =>
    postJson<GenericServiceActionResult>(`/api/engagements/${engagementId}/capabilities/custom-listener/configurations`, body),
  updateGenericService: (engagementId: string, serviceId: string, body: GenericServiceRequest) =>
    patchJson<GenericServiceActionResult>(`/api/engagements/${engagementId}/capabilities/custom-listener/configurations/${serviceId}`, body),
  disableGenericService: (engagementId: string, serviceId: string) =>
    postJson<GenericServiceActionResult>(`/api/engagements/${engagementId}/capabilities/custom-listener/configurations/${serviceId}/disable`),
  restoreGenericService: (engagementId: string, serviceId: string) =>
    postJson<GenericServiceActionResult>(`/api/engagements/${engagementId}/capabilities/custom-listener/configurations/${serviceId}/restore`),
  removeGenericService: (engagementId: string, serviceId: string) =>
    deleteJson<GenericServiceActionResult>(`/api/engagements/${engagementId}/capabilities/custom-listener/configurations/${serviceId}`),
  engagementSketchChains: (engagementId: string) =>
    getJson<{ sketchChains: SketchChainRecord[] }>(`/api/engagements/${engagementId}/sketch-chains`),
  createEngagementSketchChain: (engagementId: string, body: CreateSketchChainRequest) =>
    postJson<{ sketchChain: SketchChainRecord }>(`/api/engagements/${engagementId}/sketch-chains`, body),
  updateEngagementSketchChain: (engagementId: string, chainId: string, body: UpdateSketchChainRequest) =>
    patchJson<{ sketchChain: SketchChainRecord }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}`, body),
  cancelEngagementSketchChain: (engagementId: string, chainId: string, body: { confirmation: string }) =>
    postJson<{ sketchChain: SketchChainRecord }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/cancel`, body),
  deployEngagementSketchChain: (engagementId: string, chainId: string, body: Record<string, unknown>) =>
    postJson<SketchChainDeployResult>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/deploy`, body),
  retireEngagementSketchChainFinalEdge: (engagementId: string, chainId: string, body: { edgeId: string; confirmation: string }) =>
    postJson<{ chain: SketchChainRecord; job: JobRunDetail }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/retire`, body),
  replaceEngagementSketchChainFinalEdge: (engagementId: string, chainId: string, body: { region: string; confirmation: string }) =>
    postJson<{ chain: SketchChainRecord; job: JobRunDetail }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/replace`, body),
  keyedEdgeAppendPlanReview: (engagementId: string, chainId: string) =>
    getJson<{ review: KeyedEdgeAppendPlanReview }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/append/plan`),
  createKeyedEdgeAppendPlanReview: (engagementId: string, chainId: string) =>
    postJson<{ review: KeyedEdgeAppendPlanReview }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/append/plan`, {}),
  discardKeyedEdgeAppendPlanReview: (engagementId: string, chainId: string) =>
    postJson<{ review: KeyedEdgeAppendPlanReview }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/append/plan/discard`, {}),
  recoverNoGoKeyedEdgeAppendApply: (engagementId: string, chainId: string) =>
    postJson<{ review: KeyedEdgeAppendPlanReview }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/append/plan/recover-no-go`, {}),
  recoverKeyedEdgeAppendPublication: (engagementId: string, chainId: string) =>
    postJson<{ review: KeyedEdgeAppendPlanReview }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/append/plan/recover-publication`, {}),
  applyKeyedEdgeAppendPlanReview: (engagementId: string, chainId: string, planSha256: string) =>
    postJson<{ review: KeyedEdgeAppendPlanReview }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/edges/append/plan/apply`, { planSha256 }),
  mixedAppendPlanReview: (engagementId: string) =>
    getJson<{ review: MixedAppendPlanReview }>(`/api/engagements/${engagementId}/sketch/mixed-append/review`),
  createMixedAppendPlanReview: (engagementId: string, choices: MixedAppendEdgeChoices) =>
    postJson<{ review: MixedAppendPlanReview }>(`/api/engagements/${engagementId}/sketch/mixed-append/review`, { choices }),
  applyMixedAppendPlanReview: (engagementId: string, reviewSha256: string) =>
    postJson<{ review: MixedAppendPlanReview }>(`/api/engagements/${engagementId}/sketch/mixed-append/apply`, { reviewSha256 }),
  refreshEngagementSketchChain: (engagementId: string, chainId: string) =>
    postJson<SketchChainRefreshResult>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/refresh`),
  stopEngagementSketchChain: (engagementId: string, chainId: string, body: { confirmation: string }) =>
    postJson<{ chain: SketchChainRecord; job: JobRunDetail }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/stop`, body),
  startEngagementSketchChain: (engagementId: string, chainId: string, body: { confirmation: string }) =>
    postJson<{ chain: SketchChainRecord; job: JobRunDetail }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/start`, body),
  teardownEngagementSketchChain: (engagementId: string, chainId: string, body: { confirmation: string }) =>
    postJson<{ chain: SketchChainRecord; job: JobRunDetail }>(`/api/engagements/${engagementId}/sketch-chains/${chainId}/teardown`, body),
  engagementSketchSshKey: (engagementId: string) =>
    getJson<{ key: SketchSshKey }>(`/api/engagements/${engagementId}/sketch-ssh-key`),
  generateEngagementSketchSshKey: (engagementId: string) =>
    postJson<{ key: SketchSshKey }>(`/api/engagements/${engagementId}/sketch-ssh-key`),
  engagementSketchSshKeyMaterial: (engagementId: string) =>
    getJson<{ keyMaterial: { key: SketchSshKey; privateKey: string; publicKey: string } }>(
      `/api/engagements/${engagementId}/sketch-ssh-key/material`
    ),
  previewEngagementSketchSshKeyRotation: (engagementId: string) =>
    postJson<{ rotation: SketchSshKeyRotationPlan }>(`/api/engagements/${engagementId}/sketch-ssh-key/rotation-preview`),
  rotateEngagementSketchSshKey: (engagementId: string, confirmation: string) =>
    postJson<{ key: SketchSshKey; previousFingerprint: string; rotation: SketchSshKeyRotationPlan }>(
      `/api/engagements/${engagementId}/sketch-ssh-key/rotate`,
      { confirmation }
    ),
  previewEngagementSketchSshKeyRemoval: (engagementId: string) =>
    postJson<{ removal: SketchSshKeyRemovalPlan }>(`/api/engagements/${engagementId}/sketch-ssh-key/removal-preview`),
  removeEngagementSketchSshKey: (engagementId: string, confirmation: string) =>
    deleteJson<{ removedKey: SketchSshKey | null; removal: SketchSshKeyRemovalPlan }>(
      `/api/engagements/${engagementId}/sketch-ssh-key`,
      { confirmation }
    ),
  archiveEngagement: (engagementId: string) =>
    postJson<{ engagement: EngagementDetail }>(`/api/engagements/${engagementId}/archive`),
  deleteEngagement: (engagementId: string) =>
    deleteJson<{ engagement: EngagementDetail }>(`/api/engagements/${engagementId}`),
  configureEngagementInfrastructure: (engagementId: string, body: ConfigureEngagementInfrastructureRequest) =>
    postJson<{ engagement: EngagementDetail }>(`/api/engagements/${engagementId}/infrastructure`, body),
  revisions: (engagementId: string) => getJson<{ revisions: DeploymentRevision[] }>(`/api/engagements/${engagementId}/revisions`),
  createRevision: (engagementId: string) => postJson<{ revision: DeploymentRevision }>(`/api/engagements/${engagementId}/revisions`),
  revision: (revisionId: string) => getJson<{ revision: DeploymentRevision }>(`/api/revisions/${revisionId}`),
  renderRevision: (revisionId: string, body: RenderRevisionRequest = {}) =>
    postJson<{ renderResult: RenderResult }>(`/api/revisions/${revisionId}/render`, body),
  jobs: (options: { limit?: number; offset?: number } = {}) => {
    const params = new URLSearchParams({
      limit: String(options.limit ?? 50),
      offset: String(options.offset ?? 0)
    });
    return getJson<{ jobs: JobRunSummary[]; pagination: JobRunPagination }>(`/api/jobs?${params.toString()}`);
  },
  job: (jobId: string) => getJson<{ job: JobRunDetail }>(`/api/jobs/${jobId}`),
  createJob: (body: Record<string, unknown>) => postJson<{ job: JobRunDetail }>("/api/jobs", body),
  runJob: (jobId: string) => postJson<{ job: JobRunDetail }>(`/api/jobs/${jobId}/run`),
  planStandardRti: (body: Record<string, unknown>) =>
    postJson<{ plan: PlanOnlyDeployment }>("/api/orchestrator/standard-rti/plan", body),
  currentCoreInfrastructurePlan: (engagementId: string) =>
    getJson<{ plan: CoreInfrastructurePlan | null }>(`/api/engagements/${engagementId}/deployment-plans/current`),
  coreInfrastructurePlan: (engagementId: string, planId: string) =>
    getJson<{ plan: CoreInfrastructurePlan }>(`/api/engagements/${engagementId}/deployment-plans/${planId}`),
  prepareCoreInfrastructurePlan: (engagementId: string, body: PrepareCoreInfrastructurePlanRequest) =>
    postJson<{ plan: CoreInfrastructurePlan }>(`/api/engagements/${engagementId}/deployment-plans`, body),
  applyCoreInfrastructurePlan: (engagementId: string, planId: string, confirmMutation: string) =>
    postJson<{ plan: CoreInfrastructurePlan; job: JobRunDetail }>(
      `/api/engagements/${engagementId}/deployment-plans/${planId}/apply`,
      { confirmMutation }
    ),
  sketchProviderCatalog: (provider: string, options: { refresh?: boolean; includeBlocked?: boolean } = {}) => {
    const params = new URLSearchParams({ provider });
    if (options.refresh) {
      params.set("refresh", "1");
    }
    if (options.includeBlocked) {
      params.set("includeBlocked", "1");
    }
    return getJson<{ catalog: SketchProviderCatalog }>(`/api/provider-catalog/sketch?${params.toString()}`);
  },
  sketchRegionPolicies: () =>
    getJson<{ policies: ProviderRegionPolicy[] }>("/api/provider-catalog/sketch/region-policies"),
  updateSketchRegionPolicy: (provider: string, allowedRegions: string[]) =>
    patchJson<{ policy: ProviderRegionPolicy }>(`/api/provider-catalog/sketch/region-policies/${encodeURIComponent(provider)}`, {
      allowedRegions
    }),
  digitalOceanSketchPreflight: () =>
    postJson<{ preflight: SketchProviderPreflight }>("/api/provider-catalog/sketch/digitalocean/preflight"),
  barraganTestingDisposableReadiness: () =>
    getJson<{ readiness: DisposableDeploymentReadiness }>("/api/orchestrator/barragan-testing/disposable/readiness"),
  runBarraganTestingDisposableDeployment: (body: RunDisposableDeploymentRequest) =>
    postJson<{ deployment: DisposableDeploymentResult }>("/api/orchestrator/barragan-testing/disposable/run", body),
  barraganTestingPilotStandardRtiReadiness: (engagementId?: string | null) => {
    const query = engagementId ? `?engagementId=${encodeURIComponent(engagementId)}` : "";
    return getJson<{ readiness: DisposableDeploymentReadiness }>(
      `/api/orchestrator/barragan-testing/pilot-standard-rti/readiness${query}`
    );
  },
  runBarraganTestingPilotStandardRti: (body: RunDisposableDeploymentRequest) =>
    postJson<{ deployment: DisposableDeploymentResult }>("/api/orchestrator/barragan-testing/pilot-standard-rti/run", body),
  startBarraganTestingPilotStandardRtiRun: (body: RunDisposableDeploymentRequest) =>
    postJson<{ job: JobRunDetail }>("/api/orchestrator/barragan-testing/pilot-standard-rti/runs", body),
  barraganTestingPilotStandardRtiRun: (jobId: string) =>
    getJson<{ job: JobRunDetail }>(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${jobId}`),
  barraganTestingPilotStandardRtiTeardownPreview: (jobId: string) =>
    getJson<{ teardown: EngagementTeardownPreview }>(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${jobId}/teardown`),
  teardownBarraganTestingPilotStandardRtiRun: (jobId: string, body: { confirmation: string; snapshotId: string }) =>
    postJson<{ job: JobRunDetail }>(`/api/orchestrator/barragan-testing/pilot-standard-rti/runs/${jobId}/teardown`, body),
  startBarraganTestingLinodeSketchRun: (body: StartLinodeSketchRunRequest) =>
    postJson<{ job: JobRunDetail }>("/api/orchestrator/barragan-testing/linode-sketch/runs", body),
  barraganTestingLinodeSketchRun: (jobId: string) =>
    getJson<{ job: JobRunDetail }>(`/api/orchestrator/barragan-testing/linode-sketch/runs/${jobId}`),
  teardownBarraganTestingLinodeSketchRun: (jobId: string) =>
    postJson<{ job: JobRunDetail }>(`/api/orchestrator/barragan-testing/linode-sketch/runs/${jobId}/teardown`),
  startBarraganTestingDigitalOceanSketchValidationRun: (body: Record<string, unknown>) =>
    postJson<{ job: JobRunDetail }>("/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs", body),
  barraganTestingDigitalOceanSketchValidationRun: (jobId: string) =>
    getJson<{ job: JobRunDetail }>(`/api/orchestrator/barragan-testing/digitalocean-sketch/validation-runs/${jobId}`)
};
