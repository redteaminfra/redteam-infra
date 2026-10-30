/* Copyright (c) 2026, Oracle and/or its affiliates. */
import { AtcSettings, defaultAtcConfiguration } from "./AtcSettings";
import type { AtcConfiguration } from "../api/client";
import { InferenceProxySettings, defaultInferenceProxyConfiguration } from "./InferenceProxySettings";
import { ProviderInventoryPanel } from "./ProviderInventoryPanel";
import { Activity, Boxes, ChevronDown, ClipboardList, Copy, Globe2, KeyRound, LaptopMinimalCheck, LayoutDashboard, ListChecks, Moon, PocketKnife, Route, Settings, Sun, Swords, Users } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  apiClient,
  AuthenticatedUser,
  BackflipsServiceApplyPreview,
  BarraganApiError,
  CertificateAsset,
  CertificateManagerWorkspace,
  CredentialSummary,
  DashboardInventory,
  DashboardOrphanCandidate,
  DeploymentRevision,
  DesktopServiceApp,
  DesktopServiceDesiredApp,
  DisposableDeploymentReadiness,
  DisposableDeploymentResult,
  DomainConfirmationRequired,
  DomainGroups,
  DomainRiskStatus,
  DomainSummary,
  EngagementDnsApplyResponse,
  EngagementDnsDiff,
  EngagementDnsDomain,
  EngagementDnsEdgeTarget,
  EngagementDnsPreview,
  EngagementDnsRecord,
  EngagementDnsWorkspace,
  EngagementWorkspaceRecord,
  EngagementCapabilityWorkspace,
  InferenceProxyConfiguration,
  InferenceProxyStatus,
  EngagementCapabilityEntry,
  CapabilitySelectionRef,
  CapabilityApplyState,
  CoreInfrastructurePlan,
  CoreInfrastructurePlanStatus,
  EngagementOperationsOverview,
  EngagementAccessPlan,
  EngagementTeamMembership,
  EngagementTeamWorkspace,
  EngagementTeardownPreview,
  GenericServiceActionResult,
  GenericServiceRequest,
  EngagementDetail,
  EngagementSummary,
  InboundChannelApplyPreview,
  InboundChannelCertificate,
  InboundChannelCertificateActionResult,
  InboundChannelCertificatePrerequisites,
  InboundChannelCertificateRequest,
  InboundChannelCertificateWorkspace,
  CertificateBindingWorkspace,
  InboundChannelCreateRequest,
  InboundChannelBatchPreview,
  InboundChannelInput,
  InboundManagedRuntime,
  InboundIngressAssessment,
  InboundRequestHeaderGateWorkspace,
  InboundValidationProfile,
  InboundValidationProfileType,
  JobEvent,
  JobRunDetail,
  KeyedEdgeAppendPlanReview,
  MixedAppendEdgeChoices,
  MixedAppendPlanReview,
  JobRunPagination,
  JobRunSummary,
  InspectorCleanupPreview,
  ObserverSettings,
  OpsecNetworkRestrictionsConfiguration,
  OperationsHealth,
  OutboundChannelApplyPreview,
  OutboundChannelInput,
  ProviderOrphanRecoveryAction,
  ProviderRegionPolicy,
  RenderResult,
  SketchChainRecord,
  SketchSshKey,
  SketchSshKeyRemovalPlan,
  SketchSshKeyRotationPlan,
  SketchProviderCatalog,
  SketchProviderPreflight,
  TemplateSummary,
  TeamImportPreview,
  TeamMember,
  TeamMemberRequest,
  TeamWorkspace,
  UpdateSketchChainRequest,
  WebStaticServiceActionResult,
  WebStaticServiceApplyPreview,
  WebStaticServiceRemovePreview,
  WebStaticServiceRequest
} from "../api/client";

type ViewKey = "dashboard" | "engagements" | "team" | "domains" | "templates" | "jobs" | "settings" | "workspace";
type EngagementTabKey = "overview" | "infrastructure" | "channels" | "capabilities" | "domains" | "certificates" | "history" | "team" | "settings";
type GlobalSettingsTabKey = "user" | "cloud-providers" | "barragan-app";
type DeploymentStepStatus = "done" | "wip" | "pending" | "failed";
type ThemeMode = "light" | "dark";

type DeploymentStep = {
  id: string;
  label: string;
  detail: string;
  status: DeploymentStepStatus;
  active?: boolean;
};

type InfrastructureCommandActivity = {
  state: "working" | "possibly_stalled";
  phase: string;
  elapsedSeconds: number;
  lastActivitySeconds: number;
  play: string;
  task: string;
};

type ProgressConsolePrimaryState = {
  label: "Current task" | "Current failure" | "Outcome" | "Status";
  text: string;
};

type SketchChainWithId = ReturnType<typeof sketchChainsWithIds>[number];

type OutboundChannelActionState = {
  activeChainId: string | null;
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: OutboundChannelApplyPreview | null;
  job: JobRunDetail | null;
  applyConfirmations: Record<string, string>;
};

type InboundChannelActionState = {
  activeChannelId: string | null;
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: InboundChannelApplyPreview | null;
  job: JobRunDetail | null;
  applyConfirmations: Record<string, string>;
  validateConfirmations: Record<string, string>;
  removeConfirmations: Record<string, string>;
};

type InboundCertificateActionState = {
  activeChannelId: string | null;
  status: "idle" | "loading" | "running" | "ready" | "error";
  message: string;
  workspace: InboundChannelCertificateWorkspace | null;
  bindingWorkspace: CertificateBindingWorkspace | null;
  job: JobRunDetail | null;
  certificateType: "letsencrypt" | "self-signed";
  acmeEmail: string;
  acmeEnvironment: "staging" | "production";
  productionConfirmation: string;
};

type InboundRequestHeaderGateActionState = {
  activeChannelId: string | null;
  channel: EngagementOperationsOverview["inboundChannels"][number] | null;
  status: "idle" | "loading" | "running" | "ready" | "error";
  message: string;
  workspace: InboundRequestHeaderGateWorkspace | null;
  job: JobRunDetail | null;
  enabled: boolean;
  headerName: string;
  token: string;
  maxRequestBodyMb: string;
  copyStatus: "idle" | "token" | "curl" | "error";
};

type BackflipsServiceActionState = {
  proxyId: string;
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: BackflipsServiceApplyPreview | null;
  job: JobRunDetail | null;
  confirmation: string;
};

type DesktopServiceActionState = {
  status: "idle" | "running" | "ready" | "error";
  message: string;
  catalog: DesktopServiceApp[];
  desiredApps: Record<string, boolean>;
  job: JobRunDetail | null;
};

type WebStaticServiceFormState = WebStaticServiceRequest;

type WebStaticServiceActionState = {
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: WebStaticServiceApplyPreview | null;
  job: JobRunDetail | null;
  result: WebStaticServiceActionResult | null;
};
type WebStaticServiceRemovalActionState = {
  activeServiceId: string | null;
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: WebStaticServiceRemovePreview | null;
  job: JobRunDetail | null;
  confirmationToken: string;
  confirmation: string;
};
type GenericServiceFormState = GenericServiceRequest;
type GenericServiceActionState = {
  activeServiceId: string | null;
  status: "idle" | "saving" | "ready" | "error";
  message: string;
};
type ServiceComposerKey = "web-static" | "generic" | "backflips";
type ObserverCheckActionState = {
  status: "idle" | "loading" | "saving" | "running" | "ready" | "error";
  message: string;
  confirmation: string;
  job: JobRunDetail | null;
};
type ServicePlacement = NonNullable<EngagementOperationsOverview["servicePlacements"]>[number];

type ProviderOrphanRecoveryActionState = {
  activeCandidateId: string | null;
  status: "idle" | "running" | "ready" | "error";
  message: string;
  job: JobRunDetail | null;
  confirmationToken: string;
  confirmationValue: string;
};

type LifecycleConsoleSource = "sketch" | "provider" | null;

type DomainAssignmentFormState = {
  domainId: string;
  engagementId: string;
  purpose: string;
  notes: string;
  confirmationToken: string;
  confirmationRequired: DomainConfirmationRequired | null;
  releaseWarningVisible: boolean;
};

type DnsEditorRecord = EngagementDnsRecord & {
  localId: string;
};

type DnsEditorState = {
  domain: EngagementDnsDomain;
  records: DnsEditorRecord[];
  step: "manage" | "preview";
  status: "idle" | "previewing" | "ready" | "applying" | "error";
  message: string;
  preview: EngagementDnsPreview | null;
};

type SketchSshKeyRotationActionState = {
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: SketchSshKeyRotationPlan | null;
  confirmation: string;
  previousFingerprint: string;
};

type SketchSshKeyRemovalActionState = {
  status: "idle" | "running" | "ready" | "error";
  message: string;
  preview: SketchSshKeyRemovalPlan | null;
  confirmation: string;
  removedFingerprint: string;
};

type ConnectionDetail = {
  role: string;
  displayName: string;
  sshAlias: string;
  publicIp: string;
  privateIp: string;
  sshUser: string;
  sshCommand: string;
  services: string[];
};

type EngagementMetadataFormState = {
  name: string;
  owner: string;
  description: string;
  documentationUrl: string;
  jiraUrl: string;
};

type SketchIntentState = {
  assignedProxy: string;
  middleProvider: string;
  middleRegion: string;
  middleSize: string;
  edgeProvider: string;
  edgeRegion: string;
  edgeSize: string;
  edgeCount: number;
  edges: { id: string; provider: string; region: string; size: string }[];
}[];

type CredentialFormState = {
  provider: string;
  alias: string;
  description: string;
  secret: string;
};

type ProviderPreflightActionState = {
  status: "idle" | "running" | "ready" | "error";
  message: string;
  result: SketchProviderPreflight | null;
};

type DigitalOceanProviderSmokeActionState = {
  status: "idle" | "running" | "ready" | "error";
  message: string;
  confirmation: string;
  job: JobRunDetail | null;
};

type InboundChannelFormState = Required<Omit<InboundChannelInput, "channelId" | "chainId" | "backendPort" | "validation" | "artifactTargets" | "ingressAssessment">> & {
  channelId: string;
};

type InboundChannelBatchRow = {
  localId: string;
  body: InboundChannelCreateRequest;
};

type HostOption = {
  value: string;
  label: string;
};

type InboundEdgeOption = HostOption & {
  chainId: string;
  componentId: string;
  hostname: string;
};

type InboundHostOptions = {
  proxies: HostOption[];
  middles: HostOption[];
  edges: InboundEdgeOption[];
  terminations: HostOption[];
};

type InboundPublicIngressPolicy = {
  edgeLabel: string;
  detail: string;
  level: "empty" | "standard" | "advanced" | "udp";
  providerLabel: string;
  standardPorts: string;
  status: string;
  title: string;
};

type OutboundChannelFormState = Required<Omit<OutboundChannelInput, "chainId">> & {
  chainId: string;
};

type AppData = {
  templates: TemplateSummary[];
  engagements: EngagementSummary[];
  jobs: JobRunSummary[];
  dashboard: DashboardInventory | null;
};

const globalNavItems = [
  { key: "dashboard" as const, label: "Dashboard", icon: LayoutDashboard },
  { key: "engagements" as const, label: "Engagements", icon: Swords },
  { key: "team" as const, label: "Team", icon: Users },
  { key: "domains" as const, label: "Domains", icon: Globe2 },
  { key: "templates" as const, label: "Templates", icon: Boxes },
  { key: "jobs" as const, label: "Jobs", icon: Activity },
  { key: "settings" as const, label: "Global Settings", icon: Settings }
];

const engagementTabs = [
  { key: "overview" as const, label: "Overview", icon: LayoutDashboard },
  { key: "infrastructure" as const, label: "Infrastructure", icon: Boxes },
  { key: "channels" as const, label: "Channels", icon: Route },
  { key: "capabilities" as const, label: "Capabilities", icon: PocketKnife },
  { key: "domains" as const, label: "DNS", icon: Globe2 },
  { key: "certificates" as const, label: "Certificates", icon: KeyRound },
  { key: "history" as const, label: "History", icon: ClipboardList },
  { key: "team" as const, label: "Team", icon: Users },
  { key: "settings" as const, label: "Settings", icon: Settings }
];

const themeStorageKey = "barragan.theme";
const selectedEngagementStorageKey = "barragan.selectedEngagementId";
const jobPageSize = 50;
const sketchProviderOptions = ["linode", "digitalocean"];
const credentialProviderOptions = ["linode", "digitalocean", "namecheap"];
const proxyOptions = ["proxy01", "proxy02"];
const inboundValidationProfileOptions: Array<{ type: InboundValidationProfileType; label: string }> = [
  { type: "temporary-listener", label: "Temporary TCP listener" },
  { type: "tcp-connect", label: "TCP reachability" },
  { type: "tcp-send-receive", label: "TCP send/expect" },
  { type: "http", label: "HTTP check" },
  { type: "udp-send-receive", label: "UDP send/expect" },
  { type: "manual", label: "Manual validation" }
];
const defaultInboundValidationProfile: InboundValidationProfile = {
  type: "temporary-listener",
  label: "Temporary TCP listener"
};
const defaultUdpInboundValidationProfile: InboundValidationProfile = {
  type: "udp-send-receive",
  label: "UDP send/expect",
  requestText: "PING",
  expectedResponse: "FF0000"
};
const defaultHttpInboundValidationProfile: InboundValidationProfile = {
  type: "http",
  label: "HTTP route check"
};

const inboundDraftUsesUdp = (draft: Pick<InboundChannelFormState, "protocol" | "mode">) =>
  draft.protocol === "UDP" || draft.mode === "udp-forward";

const defaultValidationProfileForInboundDraft = (draft: Pick<InboundChannelFormState, "protocol" | "mode">): InboundValidationProfile =>
  inboundDraftUsesUdp(draft)
    ? { ...defaultUdpInboundValidationProfile }
    : draft.protocol === "HTTP" || draft.mode === "http-openresty"
      ? { ...defaultHttpInboundValidationProfile }
      : { ...defaultInboundValidationProfile };
const sketchProviderDefaults: Record<string, { region: string; size: string }> = {
  linode: { region: "us-sea", size: "g6-nanode-1" },
  digitalocean: { region: "sfo3", size: "s-1vcpu-1gb" }
};

const seededProviderCatalogs: Record<string, SketchProviderCatalog> = Object.fromEntries(
  sketchProviderOptions.map((provider) => [
    provider,
    {
      provider,
      regions: [{ id: sketchProviderDefaults[provider].region, label: sketchProviderDefaults[provider].region, available: true }],
      sizes: [
        {
          id: sketchProviderDefaults[provider].size,
          label: sketchProviderDefaults[provider].size,
          available: true,
          vcpus: null,
          memoryMb: null,
          diskGb: null,
          priceMonthly: null,
          regions: []
        }
      ],
      defaults: { ...sketchProviderDefaults[provider] },
      source: "seed",
      cachedAt: "",
      expiresAt: "",
      warnings: [],
      regionPolicy: {
        allowedRegions: [sketchProviderDefaults[provider].region],
        includeBlocked: false
      }
    }
  ])
) as Record<string, SketchProviderCatalog>;

const defaultSketchChain = (assignedProxy: string): SketchIntentState[number] => ({
  assignedProxy,
  middleProvider: "linode",
  middleRegion: sketchProviderDefaults.linode.region,
  middleSize: sketchProviderDefaults.linode.size,
  edgeProvider: "digitalocean",
  edgeRegion: sketchProviderDefaults.digitalocean.region,
  edgeSize: sketchProviderDefaults.digitalocean.size,
  edgeCount: 2,
  edges: [1, 2].map((index) => ({ id: `edge-${String(index).padStart(2, "0")}`, provider: "digitalocean", region: sketchProviderDefaults.digitalocean.region, size: sketchProviderDefaults.digitalocean.size }))
});

const defaultSketchIntent: SketchIntentState = proxyOptions.map((proxy) => defaultSketchChain(proxy));

function proxyOptionsForTemplate(templateId: string): string[] {
  return templateId === "dev-infra" || templateId === "small-dev-infra" ? ["proxy01"] : proxyOptions;
}

const emptyCredentialForm: CredentialFormState = {
  provider: "linode",
  alias: "",
  description: "",
  secret: ""
};

const emptyInboundChannelForm: InboundChannelFormState = {
  channelId: "",
  chainId: "",
  edgeComponentId: "",
  middleComponentId: "",
  domain: "",
  protocol: "TCP",
  mode: "tcp-forward",
  externalPort: "",
  relayPort: "",
  middleRelayPort: "",
  proxyRelayPort: "",
  edge: "",
  middle: "",
  proxy: "",
  terminatesOn: "",
  service: "",
  serviceId: "",
  serviceType: "",
  internalPort: "",
  purpose: "",
  status: "Not Ready",
  validationProfile: { ...defaultInboundValidationProfile }
};

const emptyOutboundChannelForm: OutboundChannelFormState = {
  chainId: "",
  proxy: "",
  middle: "",
  edge: "",
  port: "",
  region: "",
  provider: "",
  domain: "",
  purpose: "",
  status: "Not Ready"
};

const defaultWebStaticInternalPort = "8081";
const defaultWebStaticIndexHtml = "<html><body><h1>It works!</h1></body></html>\n";
const emptyGenericServiceForm: GenericServiceFormState = {
  name: "",
  targetHost: "proxy01",
  internalPort: "18090",
  protocol: "tcp",
  scriptPath: "",
  purpose: "",
  tags: [],
  notes: "",
  validationProfile: { type: "tcp-connect", label: "TCP reachability" }
};

const emptyWebStaticServiceForm: WebStaticServiceFormState = {
  proxyId: "proxy01",
  siteName: "static-web",
  domain: "static-web.invalid",
  internalPort: defaultWebStaticInternalPort,
  indexHtml: defaultWebStaticIndexHtml
};

function ComputeProfileReview({ profile }: { profile: NonNullable<CoreInfrastructurePlan["computeProfile"]> }) {
  const number = (value: number) => value.toLocaleString("en-US");

  return (
    <section className="compute-profile-review" aria-label="Resolved compute profile">
      <div className="compute-profile-heading">
        <div>
          <h4>Resolved Compute Profile</h4>
          <p>Immutable sizing saved with this exact Terraform plan.</p>
        </div>
        <span className="immutable-profile-badge">Read-only snapshot</span>
      </div>
      <dl className="compute-profile-identity">
        <div>
          <dt>Profile</dt>
          <dd><strong>{profile.name}</strong><code>{profile.id}</code></dd>
        </div>
        <div>
          <dt>Profile fingerprint</dt>
          <dd><code>{profile.fingerprint}</code></dd>
        </div>
      </dl>
      <div className="compute-profile-roles">
        {profile.roles.map((role) => (
          <article key={role.role} aria-label={`${role.label} compute sizing`}>
            <div className="compute-role-heading">
              <h5>{role.label}</h5>
              <span>{number(role.nodeCount)} {role.nodeCount === 1 ? "node" : "nodes"}</span>
            </div>
            <dl className="compute-role-specs">
              <div className="compute-role-shape">
                <dt>Shape</dt>
                <dd><code>{role.shape}</code></dd>
              </div>
              <div>
                <dt>OCPUs</dt>
                <dd>{number(role.ocpus)}</dd>
              </div>
              <div>
                <dt>RAM</dt>
                <dd>{number(role.memoryGiB)} GB</dd>
              </div>
              <div>
                <dt>Boot volume</dt>
                <dd>{number(profile.bootVolumeSizeGiB)} GiB</dd>
              </div>
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function initialTheme(): ThemeMode {
  if (typeof window === "undefined") {
    return "dark";
  }

  const storedTheme = window.localStorage.getItem(themeStorageKey);
  if (storedTheme === "light" || storedTheme === "dark") {
    return storedTheme;
  }

  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function initialSelectedEngagementId(): string | null {
  if (typeof window === "undefined") {
    return null;
  }

  return window.localStorage.getItem(selectedEngagementStorageKey) || null;
}

export function App({ currentUser, onSignOut, onSignOutAll, onChangePassword, prefetchedDashboard }: {
  currentUser?: AuthenticatedUser;
  onSignOut?: () => void;
  onSignOutAll?: () => void;
  onChangePassword?: () => void;
  prefetchedDashboard?: DashboardInventory | null;
} = {}) {
  // WI-0196 bootstraps administrators only. Keep every narrower role read-only
  // until each operator control can be mapped to its exact backend action.
  const readOnly = Boolean(currentUser && !currentUser.roles.includes("administrator"));
  const isAdministrator = !currentUser || currentUser.roles.includes("administrator");
  const initialDashboard = dashboardResponseIsComplete(prefetchedDashboard ?? null) ? prefetchedDashboard! : null;
  const [activeView, setActiveView] = useState<ViewKey>("dashboard");
  const [activeGlobalSettingsTab, setActiveGlobalSettingsTab] = useState<GlobalSettingsTabKey>("user");
  const [activeEngagementTab, setActiveEngagementTab] = useState<EngagementTabKey>("overview");
  const [theme, setTheme] = useState<ThemeMode>(initialTheme);
  const [data, setData] = useState<AppData>({ templates: [], engagements: [], jobs: [], dashboard: initialDashboard });
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [dashboardStatus, setDashboardStatus] = useState<"loading" | "ready" | "error">(initialDashboard ? "ready" : "loading");
  const dashboardRequestSequenceRef = useRef(0);
  const prefetchedInitialDashboardPendingRef = useRef(Boolean(initialDashboard));
  const dashboardViewActiveRef = useRef(false);
  const pendingDashboardRequestRef = useRef<Promise<{ dashboard: DashboardInventory }> | null>(null);
  const auxiliaryBootstrapStartedRef = useRef(false);
  const appMountedRef = useRef(true);
  const [jobsStatus, setJobsStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [jobsPagination, setJobsPagination] = useState<JobRunPagination>({ total: 0, limit: jobPageSize, offset: 0, hasMore: false });
  const [providerOrphanRecoveryAction, setProviderOrphanRecoveryAction] = useState<ProviderOrphanRecoveryActionState>({
    activeCandidateId: null,
    status: "idle",
    message: "",
    job: null,
    confirmationToken: "",
    confirmationValue: ""
  });
  const [dashboardProviderRefreshStatus, setDashboardProviderRefreshStatus] = useState<"idle" | "running" | "ready" | "error">("idle");
  const [corePlanStatus, setCorePlanStatus] = useState<CoreInfrastructurePlanStatus | "loading">("initial");
  const [corePlan, setCorePlan] = useState<CoreInfrastructurePlan | null>(null);
  const [engagementWorkflowStatus, setEngagementWorkflowStatus] = useState<"idle" | "creating" | "compiling" | "ready" | "error">("idle");
  const [engagementWorkflowRevision, setEngagementWorkflowRevision] = useState<DeploymentRevision | null>(null);
  const [guidedEngagementName, setGuidedEngagementName] = useState("ZY01");
  const [guidedOperators, setGuidedOperators] = useState("example_operator");
  const [guidedSshEnabled, setGuidedSshEnabled] = useState(true);
  const [guidedBackflipEnabled, setGuidedBackflipEnabled] = useState(false);
  const [guidedElkEnabled, setGuidedElkEnabled] = useState(false);
  const [selectedInfrastructureTemplateId, setSelectedInfrastructureTemplateId] = useState("standard-rti");
  const [selectedDeploymentTargetName, setSelectedDeploymentTargetName] = useState("");
  const [sketchIntent, setSketchIntent] = useState<SketchIntentState>(defaultSketchIntent);
  const editorEditEpochRef = useRef({ template: 0, elk: 0, target: 0, sketch: 0 });
  const editorDirtyRef = useRef({ engagementId: null as string | null, template: false, elk: false, target: false, sketch: false });
  const [selectedEngagementId, setSelectedEngagementId] = useState<string | null>(initialSelectedEngagementId);
  const [revisionHistory, setRevisionHistory] = useState<DeploymentRevision[]>([]);
  const [revisionHistoryStatus, setRevisionHistoryStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [activeCompiledRevision, setActiveCompiledRevision] = useState<DeploymentRevision | null>(null);
  const [activeCompiledRevisionStatus, setActiveCompiledRevisionStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [selectedRevisionId, setSelectedRevisionId] = useState<string | null>(null);
  const [revisionRenderStatus, setRevisionRenderStatus] = useState<"idle" | "rendering" | "ready" | "error">("idle");
  const [revisionRenderResult, setRevisionRenderResult] = useState<RenderResult | null>(null);
  const [selectedJobDetail, setSelectedJobDetail] = useState<JobRunDetail | null>(null);
  const [selectedJobDetailStatus, setSelectedJobDetailStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [testDeployReadiness, setTestDeployReadiness] = useState<DisposableDeploymentReadiness | null>(null);
  const [engagementWorkspace, setEngagementWorkspace] = useState<EngagementWorkspaceRecord | null>(null);
  const [engagementWorkspaceStatus, setEngagementWorkspaceStatus] = useState<"idle" | "loading" | "preparing" | "ready" | "error">("idle");
  const [testDeployReadinessStatus, setTestDeployReadinessStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [testDeployRunStatus, setTestDeployRunStatus] = useState<"idle" | "running" | "ready" | "error">("idle");
  const [testDeployResult, setTestDeployResult] = useState<DisposableDeploymentResult | null>(null);
  const [testDeployRunJob, setTestDeployRunJob] = useState<JobRunDetail | null>(null);
  const activeTeardownParentRef = useRef<{ engagementId: string; id: string } | null>(null);
  const [teardownRequestState, setTeardownRequestState] = useState<"idle" | "pending" | "unconfirmed">("idle");
  const teardownRequestPending = teardownRequestState === "pending";
  const teardownRequestUnconfirmed = teardownRequestState === "unconfirmed";
  const [teardownParentLoadStatus, setTeardownParentLoadStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [infrastructureConsoleOpen, setInfrastructureConsoleOpen] = useState(false);
  const [lifecycleConsoleOpen, setLifecycleConsoleOpen] = useState(false);
  const [lifecycleConsoleSource, setLifecycleConsoleSource] = useState<LifecycleConsoleSource>(null);
  const [linodeSketchRunStatus, setLinodeSketchRunStatus] = useState<"idle" | "running" | "ready" | "error">("idle");
  const [linodeSketchRunJob, setLinodeSketchRunJob] = useState<JobRunDetail | null>(null);
  const [sketchDeploymentJobs, setSketchDeploymentJobs] = useState<JobRunDetail[]>([]);
  const [sketchChainRecords, setSketchChainRecords] = useState<SketchChainRecord[]>([]);
  const postCoreSketchObserverAttemptsRef = useRef<Record<string, number>>({});
  const [sketchChainRecordsStatus, setSketchChainRecordsStatus] = useState<"idle" | "loading" | "ready" | "saving" | "error">("idle");
  const [sketchChainMessage, setSketchChainMessage] = useState("");
  const [sketchChainTeardownTarget, setSketchChainTeardownTarget] = useState<string | null>(null);
  const [sketchChainTeardownConfirmation, setSketchChainTeardownConfirmation] = useState("");
  const [sketchChainCancelTarget, setSketchChainCancelTarget] = useState<string | null>(null);
  const [sketchChainCancelConfirmation, setSketchChainCancelConfirmation] = useState("");
  const [sketchChainPowerConfirmations, setSketchChainPowerConfirmations] = useState<Record<string, string>>({});
  const [sketchEdgeTransitionConfirmations, setSketchEdgeTransitionConfirmations] = useState<Record<string, string>>({});
  const [sketchEdgeReplacementRegions, setSketchEdgeReplacementRegions] = useState<Record<string, string>>({});
  const [testDeployConfirmation, setTestDeployConfirmation] = useState("");
  const [testDeploySshSourceCidrs, setTestDeploySshSourceCidrs] = useState("");
  const [testDeployTeardownStatus, setTestDeployTeardownStatus] = useState<"idle" | "confirming" | "running">("idle");
  const [testDeployTeardownConfirmation, setTestDeployTeardownConfirmation] = useState("");
  const [engagementTeardownPreview, setEngagementTeardownPreview] = useState<EngagementTeardownPreview | null>(null);
  const [engagementTeardownPreviewStatus, setEngagementTeardownPreviewStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [engagementOperations, setEngagementOperations] = useState<EngagementOperationsOverview | null>(null);
  const [engagementOperationsStatus, setEngagementOperationsStatus] = useState<"idle" | "loading" | "ready" | "saving" | "error">("idle");
  const [outboundChannelAction, setOutboundChannelAction] = useState<OutboundChannelActionState>({
    activeChainId: null,
    status: "idle",
    message: "",
    preview: null,
    job: null,
    applyConfirmations: {}
  });
  const [inboundChannelAction, setInboundChannelAction] = useState<InboundChannelActionState>({
    activeChannelId: null,
    status: "idle",
    message: "",
    preview: null,
    job: null,
    applyConfirmations: {},
    validateConfirmations: {},
    removeConfirmations: {}
  });
  const [backflipsServiceAction, setBackflipsServiceAction] = useState<BackflipsServiceActionState>({
    proxyId: "proxy01",
    status: "idle",
    message: "",
    preview: null,
    job: null,
    confirmation: ""
  });
  const [backflipsConsoleOpen, setBackflipsConsoleOpen] = useState(false);
  const [backflipsConsoleCopied, setBackflipsConsoleCopied] = useState(false);
  const [desktopServiceAction, setDesktopServiceAction] = useState<DesktopServiceActionState>({
    status: "idle",
    message: "",
    catalog: [],
    desiredApps: {},
    job: null
  });
  const [webStaticServiceForm, setWebStaticServiceForm] = useState<WebStaticServiceFormState>(emptyWebStaticServiceForm);
  const [webStaticServiceAction, setWebStaticServiceAction] = useState<WebStaticServiceActionState>({
    status: "idle",
    message: "",
    preview: null,
    job: null,
    result: null
  });
  const webStaticReviewSequenceRef = useRef(0);
  const webStaticReviewedRequestRef = useRef<string | null>(null);
  useEffect(() => {
    webStaticReviewSequenceRef.current += 1;
    webStaticReviewedRequestRef.current = null;
    setWebStaticServiceAction({ status: "idle", message: "", preview: null, job: null, result: null });
  }, [selectedEngagementId]);
  const [webStaticServiceRemovalAction, setWebStaticServiceRemovalAction] = useState<WebStaticServiceRemovalActionState>({
    activeServiceId: null,
    status: "idle",
    message: "",
    preview: null,
    job: null,
    confirmationToken: "",
    confirmation: ""
  });
  const [genericServiceForm, setGenericServiceForm] = useState<GenericServiceFormState>(emptyGenericServiceForm);
  const [genericServiceAction, setGenericServiceAction] = useState<GenericServiceActionState>({
    activeServiceId: null,
    status: "idle",
    message: ""
  });
  const [sketchSshKey, setSketchSshKey] = useState<SketchSshKey | null>(null);
  const [sketchSshKeyStatus, setSketchSshKeyStatus] = useState<"idle" | "loading" | "ready" | "saving" | "downloaded" | "error">("idle");
  const [sketchSshKeyRotationAction, setSketchSshKeyRotationAction] = useState<SketchSshKeyRotationActionState>({
    status: "idle",
    message: "",
    preview: null,
    confirmation: "",
    previousFingerprint: ""
  });
  const [sketchSshKeyRemovalAction, setSketchSshKeyRemovalAction] = useState<SketchSshKeyRemovalActionState>({
    status: "idle",
    message: "",
    preview: null,
    confirmation: "",
    removedFingerprint: ""
  });
  const [housekeepingItemsDraft, setHousekeepingItemsDraft] = useState("");
  const [inboundChannelDraft, setInboundChannelDraft] = useState<InboundChannelFormState>(emptyInboundChannelForm);
  const [outboundChannelDraft, setOutboundChannelDraft] = useState<OutboundChannelFormState>(emptyOutboundChannelForm);
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [credentialsStatus, setCredentialsStatus] = useState<"idle" | "loading" | "ready" | "saving" | "error">("idle");
  const [credentialForm, setCredentialForm] = useState<CredentialFormState>(emptyCredentialForm);
  const [credentialMessage, setCredentialMessage] = useState("");
  const [digitalOceanPreflightAction, setDigitalOceanPreflightAction] = useState<ProviderPreflightActionState>({
    status: "idle",
    message: "",
    result: null
  });
  const [digitalOceanProviderSmokeAction, setDigitalOceanProviderSmokeAction] = useState<DigitalOceanProviderSmokeActionState>({
    status: "idle",
    message: "",
    confirmation: "",
    job: null
  });
  const [providerCatalogs, setProviderCatalogs] = useState<Record<string, SketchProviderCatalog>>(seededProviderCatalogs);
  const [providerRegionPolicyCatalogs, setProviderRegionPolicyCatalogs] = useState<Record<string, SketchProviderCatalog>>(seededProviderCatalogs);
  const [providerRegionPolicies, setProviderRegionPolicies] = useState<Record<string, ProviderRegionPolicy>>({});
  const [providerRegionPolicyStatus, setProviderRegionPolicyStatus] = useState<"idle" | "loading" | "ready" | "saving" | "error">("idle");
  const [providerRegionPolicyMessage, setProviderRegionPolicyMessage] = useState("");
  const [providerCatalogStatus, setProviderCatalogStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const filteredProviderCatalogRequestRef = useRef<{
    generation: number;
    promise: Promise<Record<string, SketchProviderCatalog>>;
  } | null>(null);
  const filteredProviderCatalogGenerationRef = useRef(0);
  const filteredProviderCatalogReadyRef = useRef(false);
  const providerPolicyRequestRef = useRef<Promise<ProviderRegionPolicy[]> | null>(null);
  const providerPolicyReadyRef = useRef(false);
  const [observerSettings, setObserverSettings] = useState<ObserverSettings | null>(null);
  const [observerForbiddenPortsInput, setObserverForbiddenPortsInput] = useState("");
  const [observerCheckAction, setObserverCheckAction] = useState<ObserverCheckActionState>({
    status: "idle",
    message: "",
    confirmation: "",
    job: null
  });

  const refreshInspectorSettingsState = useCallback((engagementId: string) => {
    return apiClient.inspectorSettings(engagementId).then((response) => {
      setObserverSettings(response.settings);
      setObserverForbiddenPortsInput(response.settings.forbiddenTcpPorts.join(", "));
      return response.settings;
    });
  }, []);

  const loadDashboard = useCallback((options: { live?: boolean } = {}) => {
    if (!options.live && pendingDashboardRequestRef.current) {
      return pendingDashboardRequestRef.current;
    }
    if (options.live) pendingDashboardRequestRef.current = null;
    const requestSequence = ++dashboardRequestSequenceRef.current;
    setDashboardStatus("loading");
    const request = apiClient.dashboard(options).then((response) => {
      if (appMountedRef.current && requestSequence === dashboardRequestSequenceRef.current) {
        setData((current) => ({ ...current, dashboard: response.dashboard }));
        setDashboardStatus("ready");
      }
      return response;
    }).catch((error) => {
      if (appMountedRef.current && requestSequence === dashboardRequestSequenceRef.current) setDashboardStatus("error");
      throw error;
    });
    if (!options.live) {
      pendingDashboardRequestRef.current = request;
      void request.finally(() => {
        if (pendingDashboardRequestRef.current === request) pendingDashboardRequestRef.current = null;
      }).catch(() => undefined);
    }
    return request;
  }, []);

  useEffect(() => {
    appMountedRef.current = true;
    return () => {
      appMountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem(themeStorageKey, theme);
  }, [theme]);

  useEffect(() => {
    if (selectedEngagementId) {
      window.localStorage.setItem(selectedEngagementStorageKey, selectedEngagementId);
    } else {
      window.localStorage.removeItem(selectedEngagementStorageKey);
    }
  }, [selectedEngagementId]);

  useEffect(() => {
    if (auxiliaryBootstrapStartedRef.current || (activeView === "dashboard" && dashboardStatus === "loading")) {
      return;
    }
    auxiliaryBootstrapStartedRef.current = true;

    Promise.all([apiClient.templates(), apiClient.allEngagements()])
      .then(([templates, engagements]) => {
        if (!appMountedRef.current) return;
        setData((current) => ({
          ...current,
          templates: templates.templates,
          engagements: engagements.engagements
        }));
        setSelectedEngagementId((current) => {
          const activeEngagements = engagements.engagements.filter(isActiveEngagement);
          if (current && activeEngagements.some((engagement) => engagement.id === current)) {
            return current;
          }
          const stored = initialSelectedEngagementId();
          if (stored && activeEngagements.some((engagement) => engagement.id === stored)) {
            return stored;
          }
          return activeEngagements[0]?.id ?? null;
        });
        setStatus("ready");
      })
      .catch(() => {
        if (appMountedRef.current) setStatus("error");
      });
    return undefined;
  }, [activeView, dashboardStatus]);

  useEffect(() => {
    if (activeView !== "jobs" || jobsStatus !== "idle") {
      return;
    }
    // Jobs data belongs to the app, so section navigation must not discard
    // the only initial response while leaving its loading state behind.
    setJobsStatus("loading");
    void apiClient.jobs({ limit: jobPageSize, offset: 0 })
      .then((response) => {
        if (appMountedRef.current) {
          setData((current) => ({ ...current, jobs: response.jobs }));
          setJobsPagination(response.pagination);
          setJobsStatus("ready");
        }
      })
      .catch(() => {
        if (appMountedRef.current) {
          setJobsStatus("error");
        }
      });
  }, [activeView]);

  useEffect(() => {
    if (activeView !== "dashboard") {
      dashboardViewActiveRef.current = false;
      return;
    }
    if (dashboardViewActiveRef.current) {
      return;
    }
    dashboardViewActiveRef.current = true;
    if (prefetchedInitialDashboardPendingRef.current) {
      prefetchedInitialDashboardPendingRef.current = false;
      return;
    }
    void loadDashboard().catch(() => undefined);
    return undefined;
  }, [activeView]);

  useEffect(() => {
    if (activeView !== "workspace" || activeEngagementTab !== "infrastructure" || testDeployReadinessStatus !== "idle") {
      return;
    }
    setTestDeployReadinessStatus("loading");
    apiClient
      .barraganTestingPilotStandardRtiReadiness(selectedEngagementId)
      .then((response) => {
        const defaultTargetName = response.readiness.target.name;
        setTestDeployReadiness(response.readiness);
        setSelectedDeploymentTargetName((current) => current || defaultTargetName);
        setTestDeploySshSourceCidrs(response.readiness.sshIngress?.defaultSourceCidrs?.join("\n") ?? "");
        setTestDeployReadinessStatus("ready");
      })
      .catch(() => {
        setTestDeployReadinessStatus("error");
      });
  }, [activeEngagementTab, activeView, selectedEngagementId, testDeployReadinessStatus]);

  useEffect(() => {
    setTestDeployReadiness(null);
    setSelectedDeploymentTargetName("");
    setTestDeployReadinessStatus("idle");
    setEngagementWorkspace(null);
    setEngagementWorkspaceStatus("idle");
    setEngagementOperations(null);
    setEngagementOperationsStatus("idle");
    setSketchSshKey(null);
    setSketchSshKeyStatus("idle");
    setSketchSshKeyRotationAction({
      status: "idle",
      message: "",
      preview: null,
      confirmation: "",
      previousFingerprint: ""
    });
    setSketchSshKeyRemovalAction({
      status: "idle",
      message: "",
      preview: null,
      confirmation: "",
      removedFingerprint: ""
    });
    setHousekeepingItemsDraft("");
    setSketchChainRecords([]);
    setSketchChainRecordsStatus("idle");
    setSketchChainMessage("");
    setSketchChainTeardownTarget(null);
    setSketchChainTeardownConfirmation("");
    setSketchChainCancelTarget(null);
    setSketchChainCancelConfirmation("");
    setOutboundChannelAction({
      activeChainId: null,
      status: "idle",
      message: "",
      preview: null,
      job: null,
      applyConfirmations: {},
      validateConfirmations: {}
    });
    setInboundChannelAction({
      activeChannelId: null,
      status: "idle",
      message: "",
      preview: null,
      job: null,
      applyConfirmations: {},
      validateConfirmations: {},
      removeConfirmations: {}
    });
    setObserverSettings(null);
    setObserverForbiddenPortsInput("");
    setObserverCheckAction({
      status: "idle",
      message: "",
      confirmation: "",
      job: null
    });
  }, [selectedEngagementId]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || activeEngagementTab !== "infrastructure") {
      return;
    }
    let cancelled = false;
    setEngagementWorkspaceStatus("loading");
    apiClient.engagementWorkspace(engagementId)
      .then((response) => {
        if (!cancelled) {
          setEngagementWorkspace(response.workspace);
          setEngagementWorkspaceStatus("ready");
        }
      })
      .catch(() => !cancelled && setEngagementWorkspaceStatus("error"));
    return () => { cancelled = true; };
  }, [activeEngagementTab, activeView, selectedEngagementId]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    const planId = corePlan?.id;
    if (!engagementId || !planId || !["preparing", "applying"].includes(corePlan.status)) {
      return;
    }
    let cancelled = false;
    const refresh = () => {
      apiClient.coreInfrastructurePlan(engagementId, planId)
        .then((response) => {
          if (cancelled) return;
          setCorePlan(response.plan);
          setCorePlanStatus(response.plan.status);
        })
        .catch(() => {
          if (!cancelled) setCorePlanStatus("failed");
        });
    };
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [corePlan?.id, corePlan?.status, selectedEngagementId]);

  const prepareDurableWorkspace = () => {
    if (!selectedEngagementId) return;
    setEngagementWorkspaceStatus("preparing");
    apiClient.prepareEngagementWorkspace(selectedEngagementId)
      .then((response) => {
        setEngagementWorkspace(response.workspace);
        setEngagementWorkspaceStatus("ready");
      })
      .catch(() => setEngagementWorkspaceStatus("error"));
  };

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || activeEngagementTab !== "settings") {
      return;
    }
    let cancelled = false;
    setObserverCheckAction((current) => ({ ...current, status: current.job ? current.status : "loading", message: current.message || "Loading Inspector settings." }));
    apiClient
      .inspectorSettings(engagementId)
      .then((response) => {
        if (cancelled) {
          return;
        }
        setObserverSettings(response.settings);
        setObserverForbiddenPortsInput(response.settings.forbiddenTcpPorts.join(", "));
        setObserverCheckAction((current) => ({
          ...current,
          status: current.job ? current.status : "ready",
          message: response.settings.configured ? "Inspector settings loaded." : "Default Inspector settings loaded."
        }));
      })
      .catch(() => {
        if (!cancelled) {
          setObserverCheckAction((current) => ({
            ...current,
            status: "error",
            message: "Could not load Inspector settings."
          }));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activeEngagementTab, activeView, selectedEngagementId]);

  useEffect(() => {
    const jobId = observerCheckAction.job?.id;
    if (!jobId || !["queued", "running"].includes(observerCheckAction.job.status)) {
      return;
    }
    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          setObserverCheckAction((current) => ({
            ...current,
            status: finished ? (response.job.status === "succeeded" ? "ready" : "error") : "running",
            message: finished ? `Inspection ${response.job.status}.` : observerJobProgressMessage(response.job),
            job: response.job
          }));
          if (finished && selectedEngagementId) {
            void refreshInspectorSettingsState(selectedEngagementId).catch(() => undefined);
          }
        })
        .catch(() => {
          if (!cancelled) {
            setObserverCheckAction((current) => ({
              ...current,
              status: "error",
              message: "Could not refresh inspection job."
            }));
          }
        });
    };
    refresh();
    const interval = window.setInterval(refresh, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [observerCheckAction.job?.id, observerCheckAction.job?.status, refreshInspectorSettingsState, selectedEngagementId]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || !["infrastructure", "overview", "channels", "capabilities"].includes(activeEngagementTab)) {
      return;
    }
    let cancelled = false;
    setEngagementOperationsStatus("loading");
    apiClient
      .engagementOperations(engagementId)
      .then((response) => {
        if (!cancelled) {
          setEngagementOperations(response.operations);
          setHousekeepingItemsDraft(response.operations.housekeepingItems);
          setEngagementOperationsStatus("ready");
          if (activeTeardownParentRef.current?.engagementId === engagementId &&
              response.operations.teardownJob?.id === activeTeardownParentRef.current.id &&
              response.operations.teardownJob.status === "succeeded" && response.operations.teardownJob.recoveryState === "complete") {
            activeTeardownParentRef.current = null;
          }
          if (response.operations.teardownSelection?.state === "exact" &&
              response.operations.teardownJob?.recoveryState === "complete" && response.operations.teardownJob.status === "succeeded") {
            setTeardownRequestState("idle");
          }
          const cleanupLifecycle = ["cleanup_required", "tearing_down"].includes(response.operations.lifecycle?.state ?? "");
          const teardownJob = cleanupLifecycle && isEngagementTeardownAction(response.operations.teardownJob?.action) &&
            ["in_progress", "recoverable"].includes(response.operations.teardownJob.recoveryState ?? "")
            ? response.operations.teardownJob
            : null;
          // Cleanup owns this view. Never load an old deployment as a fallback
          // while the exact parent is loading or its identity is unavailable.
          // An open cleanup console stays on its exact terminal parent. The
          // historical core remains available below, and becomes the default
          // again only after the operator closes the console.
          const retainOpenCleanup = infrastructureConsoleOpen &&
            isEngagementTeardownAction(testDeployRunJob?.action) &&
            jobEngagementId(testDeployRunJob) === engagementId &&
            response.operations.teardownSelection?.state === "exact" &&
            response.operations.teardownJob?.id === testDeployRunJob?.id &&
            response.operations.teardownJob.status === "succeeded" &&
            response.operations.teardownJob.recoveryState === "complete";
          const activeJob = cleanupLifecycle ? teardownJob : teardownRequestUnconfirmed || retainOpenCleanup ? null : runningCoreDeploymentEvidence(response.operations) ?? response.operations.coreJob ?? response.operations.activeJob;
          if (
            (!testDeployRunJob || testDeployRunJob.id !== activeJob?.id) &&
            (activeJob?.action === "pilot_standard_rti_guarded_execute" || isEngagementTeardownAction(activeJob?.action)) &&
            ["queued", "running", "succeeded", "failed"].includes(activeJob.status)
          ) {
            if (isEngagementTeardownAction(activeJob.action)) {
              activeTeardownParentRef.current = { engagementId, id: activeJob.id };
              setTeardownParentLoadStatus("loading");
            }
            void apiClient.barraganTestingPilotStandardRtiRun(activeJob.id)
              .then((jobResponse) => {
                if (activeTeardownParentRef.current?.engagementId === engagementId &&
                    !isEngagementTeardownAction(jobResponse.job.action)) return;
                if (!cancelled && jobResponse.job.id === activeJob.id && jobEngagementId(jobResponse.job) === engagementId && (
                  !isEngagementTeardownAction(jobResponse.job.action) || isRecoverableEngagementTeardownJob(jobResponse.job, response.operations)
                )) {
                  setTestDeployRunJob((current) => isEngagementTeardownAction(current?.action) &&
                    !isEngagementTeardownAction(jobResponse.job.action) && ["queued", "running"].includes(current?.status ?? "")
                    ? current : jobResponse.job);
                  setTestDeployRunStatus(statusFromPilotJob(jobResponse.job));
                  if (isEngagementTeardownAction(jobResponse.job.action)) {
                    setTeardownParentLoadStatus("ready");
                    setTeardownRequestState("idle");
                  }
                } else if (!cancelled && isEngagementTeardownAction(activeJob.action)) {
                  setTeardownParentLoadStatus("error");
                }
              })
              .catch(() => { if (!cancelled && isEngagementTeardownAction(activeJob.action)) setTeardownParentLoadStatus("error"); });
          }
        }
      })
      .catch(() => {
        if (!cancelled) {
          setEngagementOperationsStatus("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [
    activeEngagementTab,
    activeView,
    selectedEngagementId,
    testDeployRunJob?.id,
    testDeployRunJob?.status,
    teardownRequestUnconfirmed,
    infrastructureConsoleOpen && testDeployRunJob?.status === "succeeded",
    outboundChannelAction.job?.id,
    outboundChannelAction.job?.status,
    inboundChannelAction.job?.id,
    inboundChannelAction.job?.status,
    webStaticServiceAction.job?.id,
    webStaticServiceAction.job?.status,
    webStaticServiceRemovalAction.job?.id,
    webStaticServiceRemovalAction.job?.status
  ]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || activeEngagementTab !== "capabilities") {
      return;
    }
    let cancelled = false;
    apiClient
      .desktopService(engagementId)
      .then((response) => {
        if (!cancelled) {
          const apps = Array.isArray(response.apps) ? response.apps : [];
          setDesktopServiceAction((current) => ({
            ...current,
            catalog: apps,
            desiredApps: desktopDesiredAppsFromCatalog(apps, engagementOperations?.servicePlacements ?? [], current.desiredApps)
          }));
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDesktopServiceAction((current) => ({
            ...current,
            status: "error",
            message: "Could not load Desktop service apps."
          }));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activeEngagementTab, activeView, engagementOperations?.servicePlacements, selectedEngagementId]);

  useEffect(() => {
    if (activeView !== "workspace" || activeEngagementTab !== "capabilities" || desktopServiceAction.catalog.length === 0) {
      return;
    }
    const placements = engagementOperations?.servicePlacements ?? [];
    if (!placements.some((placement) => placement.serviceType === "desktop-app")) {
      return;
    }
    setDesktopServiceAction((current) => {
      const desiredApps = desktopDesiredAppsFromCatalog(current.catalog, placements, current.desiredApps);
      if (booleanRecordEquals(desiredApps, current.desiredApps)) {
        return current;
      }
      return { ...current, desiredApps };
    });
  }, [activeEngagementTab, activeView, desktopServiceAction.catalog.length, engagementOperations?.servicePlacements]);

  useEffect(() => {
    const jobId = inboundChannelAction.job?.id;
    if (!jobId || !["queued", "running"].includes(inboundChannelAction.job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          setInboundChannelAction((current) => ({
            ...current,
            status: finished ? (response.job.status === "succeeded" ? "ready" : "error") : "running",
            message: finished
              ? `Inbound job ${response.job.status}.`
              : inboundJobProgressMessage(response.job),
            job: response.job
          }));
          if (finished) {
            void refreshEngagementOperations();
          }
        })
        .catch(() => {
          if (!cancelled) {
            setInboundChannelAction((current) => ({
              ...current,
              status: "error",
              message: "Could not refresh inbound channel job."
            }));
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [inboundChannelAction.job?.id, inboundChannelAction.job?.status]);

  useEffect(() => {
    const jobId = desktopServiceAction.job?.id;
    if (!jobId || !["queued", "running"].includes(desktopServiceAction.job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          const placements = desktopServicePlacementsFromJob(response.job);
          setDesktopServiceAction((current) => ({
            ...current,
            status: finished ? (response.job.status === "succeeded" ? "ready" : "error") : "running",
            message: finished
              ? response.job.status === "succeeded"
                ? "Desktop service apply succeeded."
                : "Desktop service failed. Review the progress console."
              : desktopJobProgressMessage(response.job),
            desiredApps: finished && placements.length ? desktopDesiredAppsFromCatalog(current.catalog, placements, current.desiredApps) : current.desiredApps,
            job: response.job
          }));
          if (finished) {
            void refreshEngagementOperations();
          }
        })
        .catch(() => {
          if (!cancelled) {
            setDesktopServiceAction((current) => ({
              ...current,
              status: "error",
              message: "Could not refresh Desktop service job."
            }));
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [desktopServiceAction.job?.id, desktopServiceAction.job?.status]);

  useEffect(() => {
    const jobId = webStaticServiceAction.job?.id;
    if (!jobId || !["queued", "running"].includes(webStaticServiceAction.job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          const serviceStatus = webStaticJobServiceStatus(response.job);
          setWebStaticServiceAction((current) => ({
            ...current,
            status: finished ? (response.job.status === "succeeded" ? "ready" : "error") : "running",
            message: finished ? `Static Web job ${response.job.status}.` : webStaticJobProgressMessage(response.job),
            job: response.job,
            result: current.result
              ? {
                  ...current.result,
                  job: response.job,
                  status: serviceStatus ?? current.result.status,
                  service: serviceStatus ? { ...current.result.service, status: serviceStatus } : current.result.service
                }
              : current.result
          }));
          if (finished) {
            void refreshEngagementOperations();
          }
        })
        .catch(() => {
          if (!cancelled) {
            setWebStaticServiceAction((current) => ({
              ...current,
              status: "error",
              message: "Could not refresh Static Web job."
            }));
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [webStaticServiceAction.job?.id, webStaticServiceAction.job?.status]);

  useEffect(() => {
    const jobId = webStaticServiceRemovalAction.job?.id;
    if (!jobId || !["queued", "running"].includes(webStaticServiceRemovalAction.job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          setWebStaticServiceRemovalAction((current) => ({
            ...current,
            activeServiceId: finished ? null : current.activeServiceId,
            status: finished ? (response.job.status === "succeeded" ? "ready" : "error") : "running",
            message: finished ? `Static Web removal job ${response.job.status}.` : webStaticJobProgressMessage(response.job),
            job: response.job,
            confirmationToken: finished ? "" : current.confirmationToken,
            confirmation: finished ? "" : current.confirmation
          }));
          if (finished) {
            void refreshEngagementOperations();
          }
        })
        .catch(() => {
          if (!cancelled) {
            setWebStaticServiceRemovalAction((current) => ({
              ...current,
              status: "error",
              message: "Could not refresh Static Web removal job."
            }));
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [webStaticServiceRemovalAction.job?.id, webStaticServiceRemovalAction.job?.status]);

  const inboundValidationRefreshChannel = inboundChannelAction.activeChannelId
    ? engagementOperations?.inboundChannels.find((candidate) => candidate.channelId === inboundChannelAction.activeChannelId) ?? null
    : null;
  const inboundValidationRefreshKey =
    selectedEngagementId && inboundValidationRefreshChannel && inboundChannelAwaitingValidationRefresh(inboundValidationRefreshChannel)
      ? `${selectedEngagementId}:${inboundValidationRefreshChannel.channelId}:${inboundRouteValidationStatus(inboundValidationRefreshChannel)}`
      : "";

  useEffect(() => {
    if (!selectedEngagementId || activeView !== "workspace" || activeEngagementTab !== "channels" || !inboundValidationRefreshKey) {
      return;
    }

    let cancelled = false;
    let attempts = 0;
    const refresh = () => {
      attempts += 1;
      apiClient
        .engagementOperations(selectedEngagementId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          setEngagementOperations(response.operations);
          setHousekeepingItemsDraft(response.operations.housekeepingItems);
          setEngagementOperationsStatus("ready");
        })
        .catch(() => {
          if (!cancelled) {
            setEngagementOperationsStatus("error");
          }
        });
    };

    const interval = window.setInterval(() => {
      if (attempts >= 24) {
        window.clearInterval(interval);
        return;
      }
      refresh();
    }, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [
    activeEngagementTab,
    activeView,
    inboundValidationRefreshKey,
    selectedEngagementId
  ]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || !["infrastructure", "overview", "channels"].includes(activeEngagementTab)) {
      return;
    }
    let cancelled = false;
    setSketchChainRecordsStatus((current) => (current === "saving" ? current : "loading"));
    apiClient
      .engagementSketchChains(engagementId)
      .then((response) => {
        if (!cancelled) {
          setSketchChainRecords(response.sketchChains ?? []);
          setSketchChainRecordsStatus("ready");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSketchChainRecordsStatus("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activeEngagementTab, activeView, selectedEngagementId, linodeSketchRunJob?.id, linodeSketchRunJob?.status]);

  useEffect(() => {
    if (!selectedEngagementId || activeView !== "workspace" || !["infrastructure", "overview", "channels"].includes(activeEngagementTab)) {
      return;
    }
    const loadedJobIds = new Set(sketchDeploymentJobs.map((job) => job.id));
    const missingJobIds = Array.from(new Set(
      sketchChainRecords
        .filter(retainedSketchChainFieldsPresent)
        .map((chain) => chain.deployJobId)
        .filter((jobId) => !loadedJobIds.has(jobId))
    ));
    if (!missingJobIds.length) {
      return;
    }
    let cancelled = false;
    Promise.all(missingJobIds.map((jobId) => apiClient.job(jobId).catch(() => null)))
      .then((responses) => {
        if (!cancelled) {
          setSketchDeploymentJobs((current) => responses
            .filter((response): response is { job: JobRunDetail } => response !== null)
            .map((response) => response.job)
            .reduce(upsertJobDetail, current));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [
    activeEngagementTab,
    activeView,
    selectedEngagementId,
    sketchChainRecords.map((chain) => `${chain.chainId}:${chain.status}:${chain.deployJobId}:${chain.nodes.length}`).join("|"),
    sketchDeploymentJobs.map((job) => job.id).join("|")
  ]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    const activeRevisionId = data.engagements.find((engagement) => engagement.id === engagementId)?.activeRevision;
    if (!engagementId || !activeRevisionId || activeView !== "workspace") {
      return;
    }
    let cancelled = false;
    setActiveCompiledRevisionStatus("loading");
    apiClient.revisions(engagementId)
      .then((response) => {
        if (cancelled) return;
        const revision = response.revisions.find((candidate) => candidate.id === activeRevisionId) ?? null;
        setActiveCompiledRevision(revision);
        setActiveCompiledRevisionStatus(revision?.status === "compiled" ? "ready" : "error");
      })
      .catch(() => !cancelled && setActiveCompiledRevisionStatus("error"));
    return () => { cancelled = true; };
  }, [activeView, data.engagements, selectedEngagementId]);

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || activeEngagementTab !== "overview" || sketchSshKeyStatus !== "idle") {
      return;
    }
    let cancelled = false;
    setSketchSshKeyStatus("loading");
    apiClient
      .engagementSketchSshKey(engagementId)
      .then((response) => {
        if (!cancelled) {
          setSketchSshKey(response.key);
          setSketchSshKeyStatus("ready");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setSketchSshKeyStatus("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [activeEngagementTab, activeView, selectedEngagementId]);

  useEffect(() => {
    const activeEngagementId = selectedEngagementId;
    if (!activeEngagementId) {
      return;
    }
    if (testDeployRunJob && jobEngagementId(testDeployRunJob) !== activeEngagementId) {
      setTestDeployRunJob(null);
      setTestDeployRunStatus("idle");
      setTestDeployResult(null);
      setLinodeSketchRunJob(null);
      setLinodeSketchRunStatus("idle");
      setSketchDeploymentJobs([]);
      postCoreSketchObserverAttemptsRef.current = {};
      setTestDeployTeardownStatus("idle");
      setTestDeployTeardownConfirmation("");
    }
  }, [selectedEngagementId, testDeployRunJob]);

  useEffect(() => {
    if (activeView !== "settings" || !isAdministrator || credentialsStatus !== "idle") {
      return;
    }
    setCredentialsStatus("loading");
    apiClient
      .credentials()
      .then((response) => {
        setCredentials(response.credentials);
        setCredentialsStatus("ready");
      })
      .catch(() => {
      setCredentialsStatus("error");
    });
  }, [activeView, credentialsStatus, isAdministrator]);

  const dashboardStats = useMemo(
    () => [
      { label: "Engagements", value: data.dashboard?.summary.engagements ?? 0 },
      { label: "Active Infrastructure", value: data.dashboard?.summary.activeInfrastructure ?? 0 },
      { label: "Needs Attention", value: data.dashboard?.summary.attention ?? 0 },
      { label: "Torn Down 30d", value: data.dashboard?.summary.recentTeardowns ?? 0 },
      { label: "Archived 30d", value: data.dashboard?.summary.recentArchives ?? 0 },
      { label: "Provider Findings", value: data.dashboard?.summary.orphanCandidates ?? 0 }
    ],
    [data]
  );

  const guidedOperatorsList = useMemo(
    () =>
      guidedOperators
        .split(/[,\n]/)
        .map((operator) => operator.trim())
        .filter(Boolean),
    [guidedOperators]
  );

  const selectedEngagement =
    data.engagements.find((engagement) => engagement.id === selectedEngagementId) ??
    data.engagements.find((engagement) => isActiveEngagement(engagement)) ??
    null;
  const activeEngagements = data.engagements.filter(isActiveEngagement);

  useEffect(() => {
    if (!selectedEngagement?.templateId) {
      return;
    }
    setSelectedInfrastructureTemplateId(selectedEngagement.templateId);
    setGuidedElkEnabled(selectedEngagement.inputParameters?.elkEnabled === true);
    const allowedProxies = proxyOptionsForTemplate(selectedEngagement.templateId);
    setSketchIntent((current) => {
      const kept = current.filter((chain) => allowedProxies.includes(chain.assignedProxy));
      return kept.length ? kept : allowedProxies.map((proxy) => defaultSketchChain(proxy));
    });
  }, [selectedEngagement?.id]);

  useEffect(() => {
    const engagementId = selectedEngagement?.id;
    if (!engagementId) return;
    if (editorDirtyRef.current.engagementId !== engagementId) {
      editorDirtyRef.current = { engagementId, template: false, elk: false, target: false, sketch: false };
    }
    let cancelled = false;
    const editEpoch = { ...editorEditEpochRef.current };
    apiClient.engagement(engagementId).then(({ engagement }) => {
      if (cancelled || engagement.id !== engagementId) return;
      const parameters = engagement.inputParameters;
      if (!editorDirtyRef.current.template && editorEditEpochRef.current.template === editEpoch.template) {
        setSelectedInfrastructureTemplateId(engagement.templateId ?? "standard-rti");
      }
      if (!editorDirtyRef.current.elk && editorEditEpochRef.current.elk === editEpoch.elk) {
        setGuidedElkEnabled(parameters.elkEnabled === true);
      }
      const persistedChains = sketchIntentFromInputParameters(parameters);
      if (persistedChains !== null && !editorDirtyRef.current.sketch && !editorDirtyRef.current.template && editorEditEpochRef.current.sketch === editEpoch.sketch && editorEditEpochRef.current.template === editEpoch.template) {
        setSketchIntent(persistedChains);
      }
      const target = parameters.deploymentTarget;
      if (!editorDirtyRef.current.target && editorEditEpochRef.current.target === editEpoch.target) {
        setSelectedDeploymentTargetName(
          target && typeof target === "object" && typeof (target as Record<string, unknown>).name === "string"
            ? (target as Record<string, string>).name
            : ""
        );
      }
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [selectedEngagement?.id, selectedEngagement?.activeRevision]);

  const activeSectionLabel =
    activeView === "workspace"
      ? engagementTabs.find((tab) => tab.key === activeEngagementTab)?.label ?? "Overview"
      : globalNavItems.find((item) => item.key === activeView)?.label ?? "Dashboard";

  const topbarTitle =
    activeView === "workspace"
      ? `${selectedEngagement?.name ?? guidedEngagementName} / ${activeSectionLabel}`
      : activeSectionLabel;

  const topbarEyebrow =
    activeView === "workspace"
      ? `${selectedEngagement?.status ?? "draft"} · ${selectedEngagement?.owner ?? guidedOperatorsList[0] ?? "unassigned"}`
      : "Local development";

  const selectEngagement = (engagementId: string | null) => {
    setSelectedEngagementId(engagementId);
    setRevisionHistory([]);
    setRevisionHistoryStatus("idle");
    setActiveCompiledRevision(null);
    setActiveCompiledRevisionStatus("idle");
    setEngagementWorkflowRevision(null);
    setCorePlan(null);
    setCorePlanStatus("initial");
    setSelectedRevisionId(null);
    setRevisionRenderStatus("idle");
    setRevisionRenderResult(null);
    setActiveView("workspace");
  };

  const guidedDeploymentEngagementName = selectedEngagement?.name ?? guidedEngagementName;
  const selectedInfrastructureTemplate = data.templates.find((template) => template.id === selectedInfrastructureTemplateId);
  const activeInfrastructureProxyOptions = proxyOptionsForTemplate(selectedInfrastructureTemplateId);
  const guidedDeploymentInput = useMemo(
    () => standardRtiPreviewInput(
      guidedDeploymentEngagementName.trim() || "ZY01",
      sketchIntent,
      selectedInfrastructureTemplateId,
      guidedElkEnabled,
      testDeployReadiness?.availableTargets?.find((target) => target.name === selectedDeploymentTargetName) ?? testDeployReadiness?.target
    ),
    [guidedDeploymentEngagementName, guidedElkEnabled, selectedDeploymentTargetName, selectedInfrastructureTemplateId, sketchIntent, testDeployReadiness]
  );
  const localReviewedPlanInput = useMemo(() => {
    const target = testDeployReadiness?.availableTargets?.find((candidate) => candidate.name === selectedDeploymentTargetName) ?? testDeployReadiness?.target;
    const chains = sketchChainsWithIds(sketchIntent).filter(isDeployableSketchChain).map((chain) => ({
      id: chain.id,
      assignedProxy: chain.assignedProxy,
      middle: { provider: chain.middleProvider, region: chain.middleRegion },
      edges: chain.edges.map((edge) => ({ id: edge.id, provider: edge.provider, region: edge.region }))
    }));
    return {
      configuration: {
        templateId: selectedInfrastructureTemplateId,
        core: { homebases: 1, proxies: proxyOptionsForTemplate(selectedInfrastructureTemplateId).length, elkEnabled: guidedDeploymentInput.elkEnabled },
        target: { name: target?.name ?? "", region: target?.region ?? "" },
        sshSourceCidrs: [...cidrsFromText(testDeploySshSourceCidrs)].sort()
      },
      chains
    };
  }, [guidedDeploymentInput.elkEnabled, selectedDeploymentTargetName, selectedInfrastructureTemplateId, sketchIntent, testDeployReadiness, testDeploySshSourceCidrs]);

  const corePlanMatchesEditor = useMemo(() => {
    if (
      !corePlan?.reviewedConfiguration?.templateId ||
      !corePlan.reviewedConfiguration.core ||
      !corePlan.reviewedConfiguration.target ||
      !Array.isArray(corePlan.reviewedConfiguration.sshSourceCidrs) ||
      !Array.isArray(corePlan.postCoreScope?.chains)
    ) return true;
    const reviewed = corePlan.reviewedConfiguration;
    return JSON.stringify({
      templateId: reviewed.templateId,
      core: reviewed.core,
      target: reviewed.target,
      sshSourceCidrs: [...reviewed.sshSourceCidrs].sort()
    }) === JSON.stringify(localReviewedPlanInput.configuration) &&
      JSON.stringify(corePlan.postCoreScope.chains.map((chain) => ({
        id: chain.intentId ?? chain.id,
        assignedProxy: chain.assignedProxy,
        middle: chain.middle,
        edges: chain.edges
      }))) === JSON.stringify(localReviewedPlanInput.chains);
  }, [corePlan, localReviewedPlanInput]);

  const corePlanLocallyInvalidated = Boolean(
    corePlan && ["ready", "no_changes", "failed"].includes(corePlan.status) && !corePlanMatchesEditor
  );
  const displayedCorePlan = useMemo(
    () => corePlan && corePlanLocallyInvalidated ? { ...corePlan, status: "invalidated" as const } : corePlan,
    [corePlan, corePlanLocallyInvalidated]
  );
  const displayedCorePlanStatus = corePlanLocallyInvalidated ? "invalidated" as const : corePlanStatus;

  useEffect(() => {
    const engagementId = selectedEngagementId;
    if (!engagementId || activeView !== "workspace" || activeEngagementTab !== "infrastructure") {
      return;
    }
    let cancelled = false;
    setCorePlanStatus("loading");
    apiClient.currentCoreInfrastructurePlan(engagementId)
      .then((response) => {
        if (cancelled) return;
        setCorePlan(response.plan);
        setCorePlanStatus(response.plan?.status ?? "initial");
      })
      .catch(() => {
        if (!cancelled) setCorePlanStatus("failed");
      });
    return () => { cancelled = true; };
  }, [activeEngagementTab, activeView, selectedEngagementId]);

  const deployableInitialSketchChains = useMemo(
    () => sketchChainsWithIds(sketchIntent).filter(isDeployableSketchChain),
    [sketchIntent]
  );
  const deployableCompiledSketchChains = useMemo(
    () => activeCompiledRevision?.status === "compiled"
      ? compiledRevisionSketchChains(activeCompiledRevision).filter(isDeployableSketchChain)
      : [],
    [activeCompiledRevision]
  );
  const linodeSketchChain = useMemo(
    () => deployableInitialSketchChains[0] ?? null,
    [deployableInitialSketchChains]
  );

  const upsertEngagement = (engagement: EngagementSummary | EngagementDetail) => {
    setData((current) => ({
      ...current,
      engagements: [engagement, ...current.engagements.filter((candidate) => candidate.id !== engagement.id)]
        .sort((left, right) => left.name.localeCompare(right.name))
    }));
  };

  const refreshActiveEngagementSelection = (engagement: EngagementSummary | EngagementDetail) => {
    setData((current) => {
      const engagements = [engagement, ...current.engagements.filter((candidate) => candidate.id !== engagement.id)]
        .sort((left, right) => left.name.localeCompare(right.name));
      const nextActiveId = engagements.find(isActiveEngagement)?.id ?? null;
      setSelectedEngagementId((currentSelection) =>
        currentSelection === engagement.id && !isActiveEngagement(engagement)
          ? nextActiveId
          : currentSelection ?? nextActiveId
      );
      return {
        ...current,
        engagements
      };
    });
  };

  const createMetadataEngagement = (
    metadata: EngagementMetadataFormState,
    sketchStateSchema: "split-v1" | "provider-keyed-v2"
  ) => {
    return apiClient
      .createEngagement({
        name: metadata.name,
        owner: metadata.owner,
        sketchStateSchema,
        description: metadata.description,
        documentationUrl: metadata.documentationUrl,
        jiraUrl: metadata.jiraUrl
      })
      .then((response) => {
        upsertEngagement(response.engagement);
        setSelectedEngagementId(response.engagement.id);
        setGuidedEngagementName(response.engagement.name);
        setGuidedOperators(response.engagement.owner);
        return response.engagement;
      });
  };

  const updateMetadataEngagement = (engagementId: string, metadata: EngagementMetadataFormState) => {
    return apiClient.updateEngagement(engagementId, metadata).then((response) => {
      upsertEngagement(response.engagement);
      setGuidedEngagementName(response.engagement.name);
      setGuidedOperators(response.engagement.owner);
      return response.engagement;
    });
  };

  const archiveMetadataEngagement = (engagementId: string) => {
    return apiClient.archiveEngagement(engagementId).then((response) => {
      refreshActiveEngagementSelection(response.engagement);
      return response.engagement;
    });
  };

  const deleteMetadataEngagement = (engagementId: string) => {
    return apiClient.deleteEngagement(engagementId).then((response) => {
      refreshActiveEngagementSelection(response.engagement);
      return response.engagement;
    });
  };

  const reconcileMetadataEngagement = (engagementId: string) => {
    return apiClient.reconcileEngagementLifecycle(engagementId).then((response) => {
      const current = data.engagements.find((engagement) => engagement.id === engagementId);
      if (!current) {
        throw new Error("Engagement is no longer available.");
      }
      const reconciled = { ...current, lifecycle: response.reconciliation.current };
      upsertEngagement(reconciled);
      return reconciled;
    });
  };

  const compileSelectedRevision = () => {
    if (!selectedEngagementId) {
      return;
    }
    setEngagementWorkflowStatus("compiling");
    setCorePlan(null);
    setCorePlanStatus("preparing");

    apiClient
      .configureEngagementInfrastructure(selectedEngagementId, {
        templateId: selectedInfrastructureTemplateId,
        inputParameters: guidedDeploymentInput
      })
      .then((configuration) => {
        upsertEngagement(configuration.engagement);
        return apiClient.createRevision(selectedEngagementId);
      })
      .then((response) => {
        setEngagementWorkflowRevision(response.revision);
        setRevisionRenderStatus("idle");
        setRevisionRenderResult(null);
        setRevisionHistory((current) => [
          response.revision,
          ...current.filter((revision) => revision.id !== response.revision.id)
        ]);
        setSelectedRevisionId(response.revision.id);
        setData((current) => ({
          ...current,
          engagements: current.engagements.map((engagement) =>
            engagement.id === response.revision.engagementId
              ? { ...engagement, activeRevision: response.revision.id, status: "planned" }
              : engagement
          )
        }));
        return apiClient.prepareCoreInfrastructurePlan(selectedEngagementId, {
          revisionId: response.revision.id,
          sshSourceCidrs: cidrsFromText(testDeploySshSourceCidrs)
        });
      })
      .then((response) => {
        setCorePlan(response.plan);
        setCorePlanStatus(response.plan.status);
        setEngagementWorkflowStatus(response.plan.status === "failed" ? "error" : "ready");
      })
      .catch(() => {
        setEngagementWorkflowStatus("error");
        setCorePlanStatus("failed");
      });
  };

  const loadSelectedRevisions = () => {
    if (!selectedEngagementId) {
      return;
    }
    setRevisionHistoryStatus("loading");
    apiClient
      .revisions(selectedEngagementId)
      .then((response) => {
        setRevisionHistory(response.revisions);
        setSelectedRevisionId(response.revisions[0]?.id ?? null);
        setRevisionRenderStatus("idle");
        setRevisionRenderResult(null);
        setRevisionHistoryStatus("ready");
      })
      .catch(() => {
        setRevisionHistoryStatus("error");
      });
  };

  const renderSelectedRevision = () => {
    if (!selectedRevisionId) {
      return;
    }
    setRevisionRenderStatus("rendering");
    setRevisionRenderResult(null);
    apiClient
      .renderRevision(selectedRevisionId, {
        renderDestination: "/tmp/barragan-ui-render",
        renderJobId: `job-ui-render-${selectedRevisionId}`
      })
      .then((response) => {
        setRevisionRenderResult(response.renderResult);
        setRevisionRenderStatus("ready");
      })
      .catch(() => {
        setRevisionRenderStatus("error");
      });
  };

  const selectRevision = (revisionId: string) => {
    setSelectedRevisionId(revisionId);
    setRevisionRenderStatus("idle");
    setRevisionRenderResult(null);
  };

  const loadJobDetail = (jobId: string) => {
    setSelectedJobDetailStatus("loading");
    apiClient
      .job(jobId)
      .then((response) => {
        setSelectedJobDetail(response.job);
        setSelectedJobDetailStatus("ready");
        setData((current) => ({
          ...current,
          jobs: current.jobs.map((job) =>
            job.id === response.job.id ? { ...job, status: response.job.status } : job
          )
        }));
      })
      .catch(() => {
        setSelectedJobDetailStatus("error");
      });
  };

  const loadJobsPage = (offset: number) => {
    const boundedOffset = Math.max(0, offset);
    setJobsStatus("loading");
    apiClient
      .jobs({ limit: jobPageSize, offset: boundedOffset })
      .then((response) => {
        setData((current) => ({ ...current, jobs: response.jobs }));
        setJobsPagination(response.pagination);
        setSelectedJobDetail(null);
        setSelectedJobDetailStatus("idle");
        setJobsStatus("ready");
      })
      .catch(() => {
        setJobsStatus("error");
      });
  };

  const recoverProviderOrphan = (
    candidate: DashboardOrphanCandidate,
    action: ProviderOrphanRecoveryAction,
    options: { mutation?: boolean; confirmation?: string } = {}
  ) => {
    const preserveConfirmation = providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId;
    setProviderOrphanRecoveryAction({
      activeCandidateId: candidate.candidateId,
      status: "running",
      message: "",
      job: null,
      confirmationToken: preserveConfirmation ? providerOrphanRecoveryAction.confirmationToken : "",
      confirmationValue: preserveConfirmation ? providerOrphanRecoveryAction.confirmationValue : ""
    });
    apiClient
      .recoverProviderOrphan({
        candidateId: candidate.candidateId,
        action,
        requestedBy: "operator",
        mutation: options.mutation,
        confirmation: options.confirmation
      })
      .then((response) => {
        const latestEventMessage = response.job.events[response.job.events.length - 1]?.message;
        setProviderOrphanRecoveryAction({
          activeCandidateId: candidate.candidateId,
          status: ["queued", "running"].includes(response.job.status)
            ? "running"
            : response.job.status === "failed"
              ? "error"
              : "ready",
          message:
            action === "tear_down" && !options.mutation
              ? `Teardown plan recorded. Confirmation token: ${response.confirmationToken}`
              : latestEventMessage ?? "Recovery action recorded.",
          job: response.job,
          confirmationToken: action === "tear_down" && !options.mutation ? response.confirmationToken : "",
          confirmationValue: ""
        });
        if (action === "tear_down" && options.mutation) {
          setLifecycleConsoleSource("provider");
          setLifecycleConsoleOpen(true);
        }
        return Promise.all([
          loadDashboard({ live: true }),
          selectedEngagementId ? apiClient.engagementOperations(selectedEngagementId).catch(() => null) : Promise.resolve(null)
        ]).then(([_dashboard, operations]) => {
          if (operations?.operations) {
            setEngagementOperations(operations.operations);
            setHousekeepingItemsDraft(operations.operations.housekeepingItems);
            setEngagementOperationsStatus("ready");
          }
        });
      })
      .catch((error: BarraganApiError) => {
        const errors =
          typeof error.body === "object" && error.body !== null && "errors" in error.body
            ? (error.body as { errors?: unknown }).errors
            : null;
        setProviderOrphanRecoveryAction({
          activeCandidateId: candidate.candidateId,
          status: "error",
          message: Array.isArray(errors) ? errors.map(String).join("; ") : error.message,
          job: null,
          confirmationToken: preserveConfirmation ? providerOrphanRecoveryAction.confirmationToken : "",
          confirmationValue: preserveConfirmation ? providerOrphanRecoveryAction.confirmationValue : ""
        });
      });
  };

  const refreshDashboardProviderInventory = () => {
    setDashboardProviderRefreshStatus("running");
    loadDashboard({ live: true })
      .then(() => {
        setDashboardProviderRefreshStatus("ready");
      })
      .catch(() => {
        setDashboardProviderRefreshStatus("error");
      });
  };

  const setProviderOrphanTeardownConfirmation = (candidateId: string, value: string) => {
    setProviderOrphanRecoveryAction((current) => ({
      ...current,
      activeCandidateId: candidateId,
      confirmationValue: value
    }));
  };

  const resumePilotRunFromJob = (job: JobRunDetail) => {
    if (isEngagementTeardownAction(job.action)) {
      const engagementId = jobEngagementId(job);
      if (!engagementId || !data.engagements.some((engagement) => engagement.id === engagementId)) {
        return;
      }
      setSelectedEngagementId(engagementId);
    }
    // Sealed history is navigation only. Loading the engagement obtains its
    // canonical Operations selection before any cleanup can be resumed.
    const navigateSealed = hasSealedInitialCleanup(job);
    setTestDeployRunJob(navigateSealed ? null : job);
    setTestDeployRunStatus(navigateSealed ? "idle" : statusFromPilotJob(job));
    setTestDeployResult(null);
    setActiveView("workspace");
    setActiveEngagementTab("infrastructure");
  };

  useEffect(() => {
    const jobId = selectedJobDetail?.id;
    if (activeView !== "jobs" || !jobId || !["queued", "running"].includes(selectedJobDetail.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (!cancelled) {
            setSelectedJobDetail(response.job);
            setSelectedJobDetailStatus("ready");
            setData((current) => ({
              ...current,
              jobs: current.jobs.map((job) =>
                job.id === response.job.id ? { ...job, status: response.job.status } : job
              )
            }));
          }
        })
        .catch(() => {
          if (!cancelled) {
            setSelectedJobDetailStatus("error");
          }
        });
    };

    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [activeView, selectedJobDetail?.id, selectedJobDetail?.status]);

  const runTestDeployment = (options: { recreateCore?: boolean; recreateConfirmation?: string } = {}) => {
    if (!testDeployReadiness || (!options.recreateCore && (!selectedEngagementId || !corePlan))) {
      return;
    }
    setTestDeployRunStatus("running");
    setTestDeployResult(null);
    setTestDeployRunJob(null);
    setInfrastructureConsoleOpen(true);
    const start = options.recreateCore
      ? apiClient.startBarraganTestingPilotStandardRtiRun({
        engagementId: selectedEngagementId,
        confirmMutation: testDeployReadiness.confirmationToken,
        confirmDestroyCleanup: false,
        deploymentMode: "hold_for_review",
        recreateCore: true,
        recreateConfirmation: options.recreateConfirmation ?? "",
        sshSourceCidrs: cidrsFromText(testDeploySshSourceCidrs)
      })
      : apiClient.applyCoreInfrastructurePlan(selectedEngagementId!, corePlan!.id, testDeployConfirmation);
    start
      .then((response) => {
        if ("plan" in response) {
          setCorePlan(response.plan);
          setCorePlanStatus(response.plan.status);
        }
        setTestDeployRunJob(response.job);
        setTestDeployRunStatus(statusFromPilotJob(response.job));
        setData((current) => ({
          ...current,
          jobs: [
            {
              id: response.job.id,
              action: response.job.action,
              status: response.job.status,
              target: response.job.targetId,
              createdAt: new Date().toISOString()
            },
            ...current.jobs.filter((job) => job.id !== response.job.id)
          ]
        }));
      })
      .catch(() => {
        setTestDeployRunStatus("error");
      });
  };

  const refreshTestDeploymentRun = () => {
    if (!testDeployRunJob) {
      return;
    }
    apiClient
      .barraganTestingPilotStandardRtiRun(testDeployRunJob.id)
      .then((response) => {
        setTestDeployRunJob(response.job);
        setTestDeployRunStatus(statusFromPilotJob(response.job));
        void refreshEngagementOperations();
      })
      .catch(() => {
        setTestDeployRunStatus("error");
      });
  };

  const createReplacementSketchChain = (proxy: string) => {
    if (!selectedEngagementId) {
      return;
    }
    const linodeDefaults = providerDefaults(providerCatalogs, "linode");
    const draft = {
      ...defaultSketchChain(proxy),
      middleProvider: "linode",
      middleRegion: linodeDefaults.region,
      middleSize: linodeDefaults.size,
      edgeProvider: "linode",
      edgeRegion: linodeDefaults.region,
      edgeSize: linodeDefaults.size
    };
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .createEngagementSketchChain(selectedEngagementId, sketchChainRequest({ ...draft, id: "", sourceIndex: -1 }))
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.sketchChain));
        setSketchChainRecordsStatus("ready");
        setSketchChainMessage(`${response.sketchChain.chainId} added as a pending replacement chain.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not add sketch chain.");
      });
  };

  const deploySketchChainRecord = (chain: SketchChainRecord) => {
    const deployJob = sketchDeploymentJobs.find((job) => job.id === chain.deployJobId) ?? null;
    if (
      !selectedEngagementId ||
      (chain.status !== "pending" && !retainedSketchBootstrapEligible(chain, deployJob))
    ) {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .deployEngagementSketchChain(selectedEngagementId, chain.chainId, {
        confirmMutation: sketchDeployConfirmationToken(chain),
        coreJobId: testDeployRunJob?.id ?? "",
        ...(chain.status === "failed" ? { retryBootstrapOnly: true } : {})
      })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.chain));
        setLinodeSketchRunJob(response.job);
        setLinodeSketchRunStatus(statusFromPilotJob(response.job));
        setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
        setLifecycleConsoleSource("sketch");
        setLifecycleConsoleOpen(true);
        setSketchChainRecordsStatus("ready");
        setSketchChainMessage(sketchOutboundAutoConfigMessage(response) || `${response.chain.chainId} deployment started.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not deploy sketch chain.");
      });
  };

  const markSketchChainBurned = (chain: SketchChainRecord) => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .updateEngagementSketchChain(selectedEngagementId, chain.chainId, {
        burned: !chain.burned,
        burnedNote: chain.burned ? "" : "Marked burned by operator."
      })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.sketchChain));
        setSketchChainRecordsStatus("ready");
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not update burned state.");
      });
  };

  const updateSketchChainRecord = (chain: SketchChainRecord, patch: UpdateSketchChainRequest) => {
    if (!selectedEngagementId || chain.status !== "pending") {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .updateEngagementSketchChain(selectedEngagementId, chain.chainId, patch)
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.sketchChain));
        setSketchChainRecordsStatus("ready");
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not update pending sketch chain.");
      });
  };

  const cancelSketchChainRecord = (chain: SketchChainRecord) => {
    if (!selectedEngagementId || sketchChainCancelConfirmation !== `cancel-${chain.chainId}`) {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .cancelEngagementSketchChain(selectedEngagementId, chain.chainId, {
        confirmation: sketchChainCancelConfirmation
      })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.sketchChain));
        setSketchChainRecordsStatus("ready");
        setSketchChainCancelTarget(null);
        setSketchChainCancelConfirmation("");
        setSketchChainMessage(`${response.sketchChain.chainId} was canceled.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not cancel pending sketch chain.");
      });
  };

  const teardownSketchChainRecord = (chain: SketchChainRecord) => {
    if (!selectedEngagementId || sketchChainTeardownConfirmation !== `teardown-${chain.chainId}`) {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .teardownEngagementSketchChain(selectedEngagementId, chain.chainId, {
        confirmation: sketchChainTeardownConfirmation
      })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.chain));
        setLinodeSketchRunJob(response.job);
        setLinodeSketchRunStatus(statusFromPilotJob(response.job));
        setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
        setLifecycleConsoleSource("sketch");
        setLifecycleConsoleOpen(true);
        setSketchChainRecordsStatus("ready");
        setSketchChainTeardownTarget(null);
        setSketchChainTeardownConfirmation("");
        setSketchChainMessage(`${response.chain.chainId} teardown job started.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not tear down sketch chain.");
      });
  };

  const updateSketchChainPowerConfirmation = (chainId: string, value: string) => {
    setSketchChainPowerConfirmations((current) => ({ ...current, [chainId]: value }));
  };

  const retireSketchChainFinalEdge = (chain: SketchChainRecord) => {
    if (!selectedEngagementId) return;
    const edge = effectiveSketchChainEdges(chain).at(-1);
    if (!edge) return;
    const key = `${chain.chainId}:retire`;
    const confirmation = sketchEdgeTransitionConfirmations[key] ?? "";
    if (confirmation !== `retire-edge-${chain.chainId}-${edge.id}`) return;
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient.retireEngagementSketchChainFinalEdge(selectedEngagementId, chain.chainId, { edgeId: edge.id, confirmation })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.chain));
        setLinodeSketchRunJob(response.job);
        setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
        setLifecycleConsoleSource("sketch");
        setLifecycleConsoleOpen(true);
        setSketchChainRecordsStatus("ready");
        setSketchEdgeTransitionConfirmations((current) => ({ ...current, [key]: "" }));
        setSketchChainMessage(`${edge.id} retirement started; the shared middle is retained.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not retire the final sketch edge.");
      });
  };

  const replaceSketchChainFinalEdge = (chain: SketchChainRecord) => {
    if (!selectedEngagementId) return;
    const region = sketchEdgeReplacementRegions[chain.chainId] ?? "";
    const key = `${chain.chainId}:replace`;
    const confirmation = sketchEdgeTransitionConfirmations[key] ?? "";
    if (!region || confirmation !== `replace-edge-${chain.chainId}-${region}`) return;
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient.replaceEngagementSketchChainFinalEdge(selectedEngagementId, chain.chainId, { region, confirmation })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.chain));
        setLinodeSketchRunJob(response.job);
        setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
        setLifecycleConsoleSource("sketch");
        setLifecycleConsoleOpen(true);
        setSketchChainRecordsStatus("ready");
        setSketchEdgeTransitionConfirmations((current) => ({ ...current, [key]: "" }));
        setSketchChainMessage(`Replacement edge in ${region} started; Barragan will bootstrap and validate its outbound profile.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not add the replacement sketch edge.");
      });
  };

  const stopSketchChainRecord = (chain: SketchChainRecord) => {
    if (!selectedEngagementId) {
      return;
    }
    const confirmation = sketchChainPowerConfirmations[chain.chainId] ?? "";
    if (confirmation !== `stop-${chain.chainId}`) {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .stopEngagementSketchChain(selectedEngagementId, chain.chainId, { confirmation })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.chain));
        setLinodeSketchRunJob(response.job);
        setLinodeSketchRunStatus(statusFromPilotJob(response.job));
        setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
        setSketchChainRecordsStatus("ready");
        setSketchChainPowerConfirmations((current) => ({ ...current, [chain.chainId]: "" }));
        setSketchChainMessage(`${response.chain.chainId} stopped through provider power operation.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not stop sketch chain.");
      });
  };

  const startSketchChainRecord = (chain: SketchChainRecord) => {
    if (!selectedEngagementId) {
      return;
    }
    const confirmation = sketchChainPowerConfirmations[chain.chainId] ?? "";
    if (confirmation !== `start-${chain.chainId}`) {
      return;
    }
    setSketchChainRecordsStatus("saving");
    setSketchChainMessage("");
    apiClient
      .startEngagementSketchChain(selectedEngagementId, chain.chainId, { confirmation })
      .then((response) => {
        setSketchChainRecords((current) => upsertSketchChain(current, response.chain));
        setLinodeSketchRunJob(response.job);
        setLinodeSketchRunStatus(statusFromPilotJob(response.job));
        setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
        setSketchChainRecordsStatus("ready");
        setSketchChainPowerConfirmations((current) => ({ ...current, [chain.chainId]: "" }));
        setSketchChainMessage(`${response.chain.chainId} started through provider power operation.`);
      })
      .catch(() => {
        setSketchChainRecordsStatus("error");
        setSketchChainMessage("Could not start sketch chain.");
      });
  };

  const refreshSketchInfrastructureState = async () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchChainRecordsStatus("loading");
    setSketchChainMessage("");
    const knownJobIds = [
      ...sketchDeploymentJobs.map((job) => job.id),
      linodeSketchRunJob?.id ?? "",
      ...sketchChainRecords.flatMap((chain) => [chain.deployJobId, chain.teardownJobId])
    ].filter(Boolean);
    const jobIdsToRefresh = Array.from(new Set(knownJobIds));
    try {
      const refreshedJobs = await Promise.all(jobIdsToRefresh.map((jobId) => apiClient.job(jobId).then((response) => response.job)));
      if (refreshedJobs.length) {
        setSketchDeploymentJobs((current) => refreshedJobs.reduce(upsertJobDetail, current));
        const latestJob = refreshedJobs[refreshedJobs.length - 1];
        setLinodeSketchRunJob(latestJob);
        const anyRunning = refreshedJobs.some((job) => ["queued", "running"].includes(job.status));
        const anyFailed = refreshedJobs.some((job) => job.status === "failed");
        setLinodeSketchRunStatus(anyRunning ? "running" : anyFailed ? "error" : "ready");
        await Promise.all(refreshedJobs.map((job) => refreshSketchChainFromJob(job)));
      } else {
        setLinodeSketchRunStatus("idle");
      }
      const [chains] = await Promise.all([
        apiClient.engagementSketchChains(selectedEngagementId),
        refreshEngagementOperations()
      ]);
      setSketchChainRecords(chains.sketchChains ?? []);
      setSketchChainRecordsStatus("ready");
      setSketchChainMessage("Sketch chains refreshed.");
    } catch {
      setSketchChainRecordsStatus("error");
      setLinodeSketchRunStatus("error");
      setSketchChainMessage("Could not refresh sketch chain state.");
    }
  };

  const refreshLinodeSketchRun = () => {
    void refreshSketchInfrastructureState();
  };

  const refreshSketchChainFromJob = (job: JobRunDetail) => {
    const chainId = String(job.input.chainId ?? "");
    if (!selectedEngagementId || !chainId) {
      return Promise.resolve(null);
    }
    return apiClient
      .refreshEngagementSketchChain(selectedEngagementId, chainId)
      .then((response) => {
        if (response.sketchChain) {
          setSketchChainRecords((current) => upsertSketchChain(current, response.sketchChain));
        }
        const outboundAutoConfigMessage = sketchOutboundAutoConfigMessage(response);
        if (outboundAutoConfigMessage) {
          setSketchChainMessage(outboundAutoConfigMessage);
        }
        return response;
      })
      .catch(() => {
        // Job status remains the primary progress signal; failed chain refresh is non-fatal in the UI.
        return null;
      });
  };

  const saveHousekeepingItems = () => {
    if (!selectedEngagementId) {
      return;
    }
    setEngagementOperationsStatus("saving");
    apiClient
      .updateEngagementOperations(selectedEngagementId, { housekeepingItems: housekeepingItemsDraft })
      .then((response) => {
        setEngagementOperations(response.operations);
        setHousekeepingItemsDraft(response.operations.housekeepingItems);
        setEngagementOperationsStatus("ready");
      })
      .catch(() => {
        setEngagementOperationsStatus("error");
      });
  };

  const recordChannels = () => {
    if (!selectedEngagementId) {
      return;
    }
    const currentInboundChannels = engagementOperations?.inboundChannels.map(inboundChannelToInput) ?? [];
    const currentOutboundChannels = engagementOperations?.outboundChannels.map(outboundChannelToInput) ?? [];
    const nextInboundChannels = inboundChannelReady(inboundChannelDraft)
      ? upsertInboundChannel(currentInboundChannels, inboundChannelDraft)
      : null;
    const nextOutboundChannels = outboundChannelReady(outboundChannelDraft)
      ? upsertOutboundChannel(currentOutboundChannels, outboundChannelDraft)
      : null;
    const body = {
      ...(nextOutboundChannels ? { outboundChannels: nextOutboundChannels } : {}),
      ...(nextInboundChannels ? { inboundChannels: nextInboundChannels } : {})
    };
    if (!body.inboundChannels?.length && !body.outboundChannels?.length) {
      return;
    }
    setEngagementOperationsStatus("saving");
    apiClient
      .updateEngagementOperations(selectedEngagementId, body)
      .then((response) => {
        setEngagementOperations(response.operations);
        setHousekeepingItemsDraft(response.operations.housekeepingItems);
        setInboundChannelDraft(emptyInboundChannelForm);
        setOutboundChannelDraft(emptyOutboundChannelForm);
        setEngagementOperationsStatus("ready");
      })
      .catch((error) => {
        setInboundChannelAction((current) => ({
          ...current,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not record channel changes.")
        }));
        setEngagementOperationsStatus("error");
      });
  };

  const editInboundChannel = (channel: EngagementOperationsOverview["inboundChannels"][number]) => {
    if (inboundChannelHasLiveArtifacts(channel)) {
      setInboundChannelAction((current) => ({
        ...current,
        activeChannelId: channel.channelId,
        status: "error",
        message: "Applied inbound channels must be removed before changing route fields."
      }));
      setActiveEngagementTab("channels");
      return;
    }
    setInboundChannelDraft(inboundChannelToForm(channel));
    setActiveEngagementTab("channels");
  };

  const disableInboundChannel = (channel: EngagementOperationsOverview["inboundChannels"][number]) => {
    if (!selectedEngagementId || !engagementOperations) {
      return;
    }
    const nextInboundChannels = engagementOperations.inboundChannels.map((candidate) =>
      candidate.channelId === channel.channelId
        ? {
            ...inboundChannelToInput(candidate),
            status: "Disabled",
            validation: {
              ...(candidate.validation ?? {}),
              status: "Disabled",
              detail: "Operator disabled this inbound channel in Barragan."
            }
          }
        : inboundChannelToInput(candidate)
    );
    setEngagementOperationsStatus("saving");
    apiClient
      .updateEngagementOperations(selectedEngagementId, { inboundChannels: nextInboundChannels })
      .then((response) => {
        setEngagementOperations(response.operations);
        setHousekeepingItemsDraft(response.operations.housekeepingItems);
        setEngagementOperationsStatus("ready");
      })
      .catch(() => {
        setInboundChannelAction((current) => ({
          ...current,
          status: "error",
          message: "Could not disable inbound channel."
        }));
        setEngagementOperationsStatus("error");
      });
  };

  const removeInboundChannel = (channel: EngagementOperationsOverview["inboundChannels"][number]) => {
    if (!selectedEngagementId || !engagementOperations) {
      return;
    }
    const confirmation = inboundChannelRequiresRemoveConfirmation(channel) ? removeInboundConfirmationToken(channel.channelId) : "";
    setInboundChannelAction((current) => ({
      ...current,
      activeChannelId: channel.channelId,
      status: "running",
      message: inboundChannelRequiresRemoveConfirmation(channel) ? "Removing live inbound channel config." : "Removing inbound channel record.",
      job: null
    }));
    apiClient
      .removeInboundChannel(selectedEngagementId, channel.channelId, confirmation)
      .then((response) => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channel.channelId,
          status: "ready",
          message: `Inbound removal returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        void refreshEngagementOperations();
      })
      .catch(() => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channel.channelId,
          status: "error",
          message: "Could not remove inbound channel config."
        }));
      });
  };

  const refreshEngagementOperations = () => {
    if (!selectedEngagementId) {
      return Promise.resolve(null);
    }
    setEngagementOperationsStatus("loading");
    return apiClient
      .engagementOperations(selectedEngagementId)
      .then((response) => {
        setEngagementOperations(response.operations);
        setHousekeepingItemsDraft(response.operations.housekeepingItems);
        setEngagementOperationsStatus("ready");
        return response.operations;
      })
      .catch(() => {
        setEngagementOperationsStatus("error");
        return null;
      });
  };

  const createInboundChannel = (body: InboundChannelCreateRequest) => {
    if (!selectedEngagementId) {
      return;
    }
    setInboundChannelAction((current) => ({
      ...current,
      activeChannelId: null,
      status: "running",
      message: "Creating, applying, and validating inbound channel.",
      job: null
    }));
    apiClient
      .createInboundChannel(selectedEngagementId, body)
      .then((response) => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: response.channel.channelId ?? null,
          status: ["queued", "running"].includes(response.job.status) ? "running" : "ready",
          message: `Inbound channel ${response.channel.channelId ?? "route"} apply started; validation will run automatically after apply succeeds.`,
          job: response.job
        }));
        void refreshEngagementOperations();
      })
      .catch((error) => {
        setInboundChannelAction((current) => ({
          ...current,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not create inbound channel.")
        }));
      });
  };

  const recoverInboundChannel = (channel: EngagementOperationsOverview["inboundChannels"][number]) => {
    if (!selectedEngagementId) {
      return;
    }
    setInboundChannelAction((current) => ({
      ...current,
      activeChannelId: channel.channelId,
      status: "running",
      message: "Restoring, applying, and validating inbound channel.",
      job: null
    }));
    apiClient
      .recoverInboundChannel(selectedEngagementId, channel.channelId)
      .then((response) => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: response.channel.channelId ?? channel.channelId,
          status: ["queued", "running"].includes(response.job.status) ? "running" : "ready",
          message: `Inbound channel ${response.channel.channelId ?? channel.channelId} restore apply started; validation will run automatically after apply succeeds.`,
          job: response.job
        }));
        void refreshEngagementOperations();
      })
      .catch((error) => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channel.channelId,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not restore inbound channel.")
        }));
      });
  };

  const updateOutboundChannelConfirmation = (chainId: string, value: string) => {
    setOutboundChannelAction((current) => ({
      ...current,
      applyConfirmations: {
        ...current.applyConfirmations,
        [chainId]: value
      }
    }));
  };

  const updateInboundChannelConfirmation = (channelId: string, kind: "apply" | "validate" | "remove", value: string) => {
    const confirmationKey =
      kind === "apply" ? "applyConfirmations" : kind === "validate" ? "validateConfirmations" : "removeConfirmations";
    setInboundChannelAction((current) => ({
      ...current,
      [confirmationKey]: {
        ...current[confirmationKey],
        [channelId]: value
      }
    }));
  };

  const previewOutboundChannelApply = (chainId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setOutboundChannelAction((current) => ({
      ...current,
      activeChainId: chainId,
      status: "running",
      message: "Previewing outbound channel apply plan.",
      preview: null,
      job: null
    }));
    apiClient
      .applyPreviewOutboundChannel(selectedEngagementId, chainId)
      .then((response) => {
        setOutboundChannelAction((current) => ({
          ...current,
          activeChainId: chainId,
          status: "ready",
          message: "Apply plan preview is ready.",
          preview: response,
          job: response.job
        }));
      })
      .catch(() => {
        setOutboundChannelAction((current) => ({
          ...current,
          activeChainId: chainId,
          status: "error",
          message: "Could not preview outbound channel apply plan.",
          preview: null,
          job: null
        }));
      });
  };

  const previewInboundChannelApply = (channelId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setInboundChannelAction((current) => ({
      ...current,
      activeChannelId: channelId,
      status: "running",
      message: "Previewing inbound channel apply plan.",
      preview: null,
      job: null
    }));
    apiClient
      .previewInboundChannelApply(selectedEngagementId, channelId)
      .then((response) => {
        const applyAllowed = response.workspace.ingressAssessment?.applyAllowed;
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channelId,
          status: "ready",
          message: applyAllowed === false
            ? "Inbound apply preview found a blocked ingress path."
            : "Inbound apply plan preview is ready.",
          preview: response,
          job: response.job
        }));
        return refreshEngagementOperations();
      })
      .catch(() => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channelId,
          status: "error",
          message: "Could not preview inbound channel apply plan.",
          preview: null,
          job: null
        }));
      });
  };

  const applyInboundChannel = (channelId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    const confirmation = inboundChannelAction.applyConfirmations[channelId] ?? "";
    if (confirmation !== applyInboundConfirmationToken(channelId)) {
      return;
    }
    setInboundChannelAction((current) => ({
      ...current,
      activeChannelId: channelId,
      status: "running",
      message: "Applying inbound channel config.",
      job: null
    }));
    apiClient
      .applyInboundChannel(selectedEngagementId, channelId, confirmation)
      .then((response) => {
        const stillRunning = ["queued", "running"].includes(response.job.status);
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channelId,
          status: stillRunning ? "running" : response.job.status === "succeeded" ? "ready" : "error",
          message: stillRunning ? inboundJobProgressMessage(response.job) : `Inbound apply returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        if (!stillRunning) {
          void refreshEngagementOperations();
        }
      })
      .catch((error: unknown) => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channelId,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not apply inbound channel config.")
        }));
      });
  };

  const validateInboundChannel = (channelId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    const confirmation = validateInboundConfirmationToken(channelId);
    setInboundChannelAction((current) => ({
      ...current,
      activeChannelId: channelId,
      status: "running",
      message: "Validating inbound channel from the selected edge through the route.",
      job: null
    }));
    apiClient
      .validateInboundChannel(selectedEngagementId, channelId, confirmation)
      .then((response) => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channelId,
          status: "ready",
          message: `Inbound validation returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        void refreshEngagementOperations();
      })
      .catch(() => {
        setInboundChannelAction((current) => ({
          ...current,
          activeChannelId: channelId,
          status: "error",
          message: "Could not validate inbound channel from the selected edge."
        }));
      });
  };

  const applyOutboundChannel = (chainId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    const confirmation = outboundChannelAction.applyConfirmations[chainId] ?? "";
    if (confirmation !== applyOutboundConfirmationToken(chainId)) {
      return;
    }
    setOutboundChannelAction((current) => ({
      ...current,
      activeChainId: chainId,
      status: "running",
      message: "Applying core channel config.",
      job: null
    }));
    apiClient
      .applyOutboundChannel(selectedEngagementId, chainId, confirmation)
      .then((response) => {
        setOutboundChannelAction((current) => ({
          ...current,
          activeChainId: chainId,
          status: "ready",
          message: `Core channel config returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        void refreshEngagementOperations();
      })
      .catch(() => {
        setOutboundChannelAction((current) => ({
          ...current,
          activeChainId: chainId,
          status: "error",
          message: "Could not apply core channel config."
        }));
      });
  };

  const validateOutboundChannel = (chainId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setOutboundChannelAction((current) => ({
      ...current,
      activeChainId: chainId,
      status: "running",
      message: "Validating outbound channel from homebase.",
      job: null
    }));
    apiClient
      // Re-check is non-mutating. The API's existing request guard is supplied
      // by the client so operators do not have to type a ceremony token.
      .validateOutboundChannel(selectedEngagementId, chainId, validateOutboundConfirmationToken(chainId))
      .then((response) => {
        setOutboundChannelAction((current) => ({
          ...current,
          activeChainId: chainId,
          status: "ready",
          message: `Homebase validation returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        void refreshEngagementOperations();
      })
      .catch(() => {
        setOutboundChannelAction((current) => ({
          ...current,
          activeChainId: chainId,
          status: "error",
          message: "Could not validate outbound channel from homebase."
        }));
      });
  };

  const updateBackflipsServiceAction = (patch: Partial<BackflipsServiceActionState>) => {
    setBackflipsServiceAction((current) => ({ ...current, ...patch }));
  };

  const previewBackflipsServiceApply = () => {
    if (!selectedEngagementId) {
      return;
    }
    setBackflipsServiceAction((current) => ({
      ...current,
      status: "running",
      message: `Previewing Backflips V2 prerequisites for ${current.proxyId}.`,
      preview: null,
      job: null
    }));
    apiClient
      .previewBackflipsServiceApply(selectedEngagementId, backflipsServiceAction.proxyId)
      .then((response) => {
        setBackflipsServiceAction((current) => ({
          ...current,
          status: "ready",
          message: "Backflips V2 prerequisite preview is ready.",
          preview: response,
          job: response.job
        }));
      })
      .catch(() => {
        setBackflipsServiceAction((current) => ({
          ...current,
          status: "error",
          message: "Could not preview SSH Backflips apply.",
          preview: null,
          job: null
        }));
      });
  };

  const applyBackflipsService = () => {
    if (!selectedEngagementId || backflipsServiceAction.confirmation !== backflipsApplyConfirmationToken()) {
      return;
    }
    setBackflipsServiceAction((current) => ({
      ...current,
      status: "running",
      message: `Applying Backflips V2 prerequisites to ${current.proxyId}.`,
      job: null
    }));
    apiClient
      .applyBackflipsService(
        selectedEngagementId,
        backflipsServiceAction.proxyId,
        backflipsServiceAction.confirmation
      )
      .then((response) => {
        setBackflipsServiceAction((current) => ({
          ...current,
          status: "ready",
          message: `SSH Backflips returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        setBackflipsConsoleOpen(true);
        void refreshEngagementOperations();
      })
      .catch(() => {
        setBackflipsServiceAction((current) => ({
          ...current,
          status: "error",
          message: "Could not apply SSH Backflips."
        }));
      });
  };

  const applyDesktopService = (desiredAppsOverride?: DesktopServiceDesiredApp[]) => {
    if (!selectedEngagementId || desktopServiceAction.status === "running") {
      return;
    }
    const desiredApps = desiredAppsOverride ?? desktopDesiredApps(desktopServiceAction);
    setDesktopServiceAction((current) => ({
      ...current,
      status: "running",
      message: "Applying Desktop app changes to homebase.",
      desiredApps: Object.fromEntries(desiredApps.map((app) => [app.slug, app.enabled])),
      job: null
    }));
    apiClient
      .applyDesktopCapabilities(selectedEngagementId)
      .then((response) => {
        const finished = !["queued", "running"].includes(response.job.status);
        const failed = response.job.status === "failed" || String(response.status || "").toLowerCase() === "failed";
        setDesktopServiceAction((current) => ({
          ...current,
          status: finished ? (failed ? "error" : "ready") : "running",
          message: finished
            ? failed
              ? "Desktop service failed. Review the progress console."
              : `Desktop service returned ${response.status ?? response.job.status}.`
            : desktopJobProgressMessage(response.job),
          desiredApps:
            finished && response.servicePlacements.length
              ? desktopDesiredAppsFromCatalog(current.catalog, response.servicePlacements, current.desiredApps)
              : current.desiredApps,
          job: response.job
        }));
        if (finished) {
          void refreshEngagementOperations();
        }
      })
      .catch(() => {
        setDesktopServiceAction((current) => ({
          ...current,
          status: "error",
          message: "Could not apply Desktop app changes."
        }));
      });
  };

  const updateWebStaticServiceForm = (patch: Partial<WebStaticServiceFormState>) => {
    if (Object.keys(patch).some((key) => key !== "contentAction")) {
      webStaticReviewSequenceRef.current += 1;
      webStaticReviewedRequestRef.current = null;
      setWebStaticServiceAction({ status: "idle", message: "", preview: null, job: null, result: null });
      patch = { ...patch, contentAction: "preserve" };
    }
    setWebStaticServiceForm((current) => {
      const next = { ...current, ...patch };
      if (
        patch.siteName !== undefined &&
        patch.domain === undefined &&
        (!current.domain || current.domain === `${current.siteName}.invalid`)
      ) {
        const slug = webStaticSiteSlug(patch.siteName);
        next.domain = slug ? `${slug}.invalid` : current.domain;
      }
      return next;
    });
  };

  const previewWebStaticServiceApply = () => {
    if (!selectedEngagementId || !webStaticServiceReady(webStaticServiceForm)) {
      return;
    }
    const request = webStaticServiceRequest(webStaticServiceForm);
    const sequence = ++webStaticReviewSequenceRef.current;
    webStaticReviewedRequestRef.current = null;
    setWebStaticServiceAction({
      status: "running",
      message: `Checking website files on ${webStaticServiceForm.proxyId}.`,
      preview: null,
      job: null,
      result: null
    });
    apiClient
      .previewWebStaticServiceApply(selectedEngagementId, request)
      .then((response) => {
        if (webStaticReviewSequenceRef.current !== sequence) return;
        webStaticReviewedRequestRef.current = webStaticRequestIdentity(request);
        setWebStaticServiceForm((current) => ({ ...current, contentAction: "preserve" }));
        setWebStaticServiceAction({
          status: "ready",
          message: "Static web service apply preview is ready.",
          preview: response,
          job: response.job,
          result: null
        });
      })
      .catch((error: unknown) => {
        if (webStaticReviewSequenceRef.current !== sequence) return;
        setWebStaticServiceAction({
          status: "error",
          message: barraganApiErrorSummary(error, "Could not inspect website files. Check the proxy connection and review again."),
          preview: null,
          job: null,
          result: null
        });
      });
  };

  const applyWebStaticServiceRequest = (
    request: WebStaticServiceRequest,
    options: { message: string; errorMessage: string }
  ) => {
    if (!selectedEngagementId || !webStaticServiceReady(request)) {
      return;
    }
    const review = webStaticServiceAction.preview?.contentReview;
    if (!review || webStaticReviewedRequestRef.current !== webStaticRequestIdentity(request)) {
      setWebStaticServiceAction((current) => ({ ...current, status: "error", message: "Review the current website files before applying.", preview: null }));
      return;
    }
    request = { ...request, contentReviewJobId: review.reviewJobId };
    webStaticReviewedRequestRef.current = null;
    const sequence = ++webStaticReviewSequenceRef.current;
    setWebStaticServiceAction((current) => ({
      ...current,
      status: "running",
      message: options.message,
      job: null,
      preview: null,
      result: null
    }));
    apiClient
      .applyWebStaticService(selectedEngagementId, request)
      .then((response) => {
        if (webStaticReviewSequenceRef.current !== sequence) return;
        const jobRunning = ["queued", "running"].includes(response.job.status);
        setWebStaticServiceAction((current) => ({
          ...current,
          status: jobRunning ? "running" : response.job.status === "failed" ? "error" : "ready",
          message: jobRunning ? webStaticJobProgressMessage(response.job) : `Static web service returned ${response.status ?? response.job.status}.`,
          job: response.job,
          result: response
        }));
        setEngagementOperations((current) => mergeWebStaticServicePlacement(current, response.service));
        void refreshEngagementOperations();
      })
      .catch((error: unknown) => {
        if (webStaticReviewSequenceRef.current !== sequence) return;
        setWebStaticServiceAction((current) => ({
          ...current,
          status: "error",
          preview: null,
          message: barraganApiErrorSummary(error, options.errorMessage)
        }));
      });
  };

  const applyWebStaticService = () => {
    const request = webStaticServiceRequest(webStaticServiceForm);
    applyWebStaticServiceRequest(request, {
      message: `Applying static web service ${webStaticServiceForm.siteName} to ${webStaticServiceForm.proxyId}.`,
      errorMessage: "Could not apply static web service."
    });
  };

  const restoreWebStaticService = (request: WebStaticServiceRequest) => {
    applyWebStaticServiceRequest(request, {
      message: `Restoring static web service ${request.siteName} to ${request.proxyId}.`,
      errorMessage: "Could not restore static web service."
    });
  };

  const resetWebStaticServiceAction = () => {
    webStaticReviewSequenceRef.current += 1;
    webStaticReviewedRequestRef.current = null;
    setWebStaticServiceAction({
      status: "idle",
      message: "",
      preview: null,
      job: null,
      result: null
    });
    setWebStaticServiceRemovalAction({
      activeServiceId: null,
      status: "idle",
      message: "",
      preview: null,
      job: null,
      confirmationToken: "",
    confirmation: ""
  });

  };

  const updateGenericServiceForm = (patch: Partial<GenericServiceFormState>) => {
    setGenericServiceForm((current) => {
      const next = { ...current, ...patch };
      if (patch.protocol) {
        next.validationProfile = defaultValidationProfileForGenericProtocol(patch.protocol);
      }
      return next;
    });
  };

  const saveGenericService = () => {
    if (!selectedEngagementId || !genericServiceReady(genericServiceForm)) {
      return;
    }
    const request = genericServiceRequest(genericServiceForm);
    const activeServiceId = genericServiceForm.serviceId ?? null;
    setGenericServiceAction((current) => ({
      ...current,
      status: "saving",
      message: activeServiceId ? `Updating ${request.name}.` : `Adding ${request.name}.`
    }));
    const action = activeServiceId
      ? apiClient.updateGenericService(selectedEngagementId, activeServiceId, request)
      : apiClient.createGenericService(selectedEngagementId, request);
    action
      .then((response) => {
        setGenericServiceAction({
          activeServiceId: response.service.serviceId,
          status: "ready",
          message: `${response.service.name} is ${response.service.status}.`
        });
        setGenericServiceForm(genericServiceFormFromPlacement(genericServicePlacement(response.service)));
        setEngagementOperations((current) => mergeGenericServicePlacement(current, response.service));
        void refreshEngagementOperations();
      })
      .catch((error: unknown) => {
        setGenericServiceAction((current) => ({
          ...current,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not save Custom Listener.")
        }));
      });
  };

  const disableGenericService = (serviceId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setGenericServiceAction({ activeServiceId: serviceId, status: "saving", message: `Disabling ${serviceId}.` });
    apiClient
      .disableGenericService(selectedEngagementId, serviceId)
      .then((response) => {
        setGenericServiceAction({ activeServiceId: serviceId, status: "ready", message: `${response.service.name} is disabled.` });
        setGenericServiceForm(genericServiceFormFromPlacement(genericServicePlacement(response.service)));
        setEngagementOperations((current) => mergeGenericServicePlacement(current, response.service));
        void refreshEngagementOperations();
      })
      .catch((error: unknown) => {
        setGenericServiceAction({ activeServiceId: serviceId, status: "error", message: barraganApiErrorSummary(error, "Could not disable Custom Listener.") });
      });
  };

  const restoreGenericService = (serviceId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setGenericServiceAction({ activeServiceId: serviceId, status: "saving", message: `Restoring ${serviceId}.` });
    apiClient
      .restoreGenericService(selectedEngagementId, serviceId)
      .then((response) => {
        setGenericServiceAction({ activeServiceId: serviceId, status: "ready", message: `${response.service.name} is active.` });
        setGenericServiceForm(genericServiceFormFromPlacement(genericServicePlacement(response.service)));
        setEngagementOperations((current) => mergeGenericServicePlacement(current, response.service));
        void refreshEngagementOperations();
      })
      .catch((error: unknown) => {
        setGenericServiceAction({ activeServiceId: serviceId, status: "error", message: barraganApiErrorSummary(error, "Could not restore Custom Listener.") });
      });
  };

  const removeGenericService = (serviceId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setGenericServiceAction({ activeServiceId: serviceId, status: "saving", message: `Removing ${serviceId}.` });
    apiClient
      .removeGenericService(selectedEngagementId, serviceId)
      .then((response) => {
        setGenericServiceAction({ activeServiceId: serviceId, status: "ready", message: `${response.service.name} was removed.` });
        setGenericServiceForm(genericServiceFormFromPlacement(genericServicePlacement(response.service)));
        setEngagementOperations((current) => mergeGenericServicePlacement(current, response.service));
        void refreshEngagementOperations();
      })
      .catch((error: unknown) => {
        setGenericServiceAction({ activeServiceId: serviceId, status: "error", message: barraganApiErrorSummary(error, "Could not remove Custom Listener.") });
      });
  };

  const previewWebStaticServiceRemove = (serviceId: string) => {
    if (!selectedEngagementId) {
      return;
    }
    setWebStaticServiceRemovalAction({
      activeServiceId: serviceId,
      status: "running",
      message: `Preparing removal for ${serviceId}.`,
      preview: null,
      job: null,
      confirmationToken: "",
      confirmation: ""
    });
    apiClient
      .previewWebStaticServiceRemove(selectedEngagementId, serviceId)
      .then((response) => {
        setWebStaticServiceRemovalAction({
          activeServiceId: serviceId,
          status: "ready",
          message: `Type ${response.confirmationToken} to remove generated config. Website files are preserved.`,
          preview: response,
          job: response.job,
          confirmationToken: response.confirmationToken,
          confirmation: ""
        });
      })
      .catch(() => {
        setWebStaticServiceRemovalAction({
          activeServiceId: serviceId,
          status: "error",
          message: "Could not prepare Static Web removal.",
          preview: null,
          job: null,
          confirmationToken: "",
          confirmation: ""
        });
      });
  };

  const applyWebStaticServiceRemove = () => {
    if (!selectedEngagementId || !webStaticServiceRemovalAction.activeServiceId) {
      return;
    }
    const serviceId = webStaticServiceRemovalAction.activeServiceId;
    setWebStaticServiceRemovalAction((current) => ({
      ...current,
      status: "running",
      message: `Removing generated config for ${serviceId}.`
    }));
    apiClient
      .removeWebStaticService(selectedEngagementId, serviceId, webStaticServiceRemovalAction.confirmation)
      .then((response) => {
        const jobRunning = ["queued", "running"].includes(response.job.status);
        setWebStaticServiceRemovalAction({
          activeServiceId: jobRunning ? serviceId : null,
          status: jobRunning ? "running" : response.job.status === "failed" ? "error" : "ready",
          message: jobRunning ? webStaticJobProgressMessage(response.job) : `Static Web returned ${response.status ?? response.job.status}.`,
          job: response.job,
          preview: null,
          confirmationToken: jobRunning ? webStaticServiceRemovalAction.confirmationToken : "",
          confirmation: jobRunning ? webStaticServiceRemovalAction.confirmation : ""
        });
        setEngagementOperations((current) => mergeWebStaticServicePlacement(current, response.service));
        void refreshEngagementOperations();
      })
      .catch(() => {
        setWebStaticServiceRemovalAction((current) => ({
          ...current,
          status: "error",
          message: "Could not remove Static Web generated config."
        }));
      });
  };

  const refreshCredentials = () => {
    setCredentialsStatus("loading");
    return apiClient
      .credentials()
      .then((response) => {
        setCredentials(response.credentials);
        setCredentialsStatus("ready");
        return response.credentials;
      })
      .catch(() => {
        setCredentialsStatus("error");
        return [];
      });
  };

  const refreshProviderCatalogs = useCallback((options: { includeBlocked?: boolean } = {}) => {
    return Promise.all(
      sketchProviderOptions.map((provider) =>
        apiClient
          .sketchProviderCatalog(provider, { includeBlocked: options.includeBlocked })
          .then((response) => [provider, response.catalog ?? seededProviderCatalogs[provider]] as const)
      )
    ).then((catalogs) => Object.fromEntries(catalogs) as Record<string, SketchProviderCatalog>);
  }, []);

  const refreshFilteredProviderCatalogs = useCallback((options: { force?: boolean } = {}) => {
    if (options.force) {
      filteredProviderCatalogGenerationRef.current += 1;
      filteredProviderCatalogReadyRef.current = false;
    }
    if (!options.force && filteredProviderCatalogReadyRef.current) {
      return Promise.resolve(providerCatalogs);
    }
    const generation = filteredProviderCatalogGenerationRef.current;
    const inFlight = filteredProviderCatalogRequestRef.current;
    if (inFlight?.generation === generation) {
      return inFlight.promise;
    }
    setProviderCatalogStatus("loading");
    const request = refreshProviderCatalogs()
      .then((catalogs) => {
        if (generation === filteredProviderCatalogGenerationRef.current) {
          setProviderCatalogs((current) => ({ ...current, ...catalogs }));
          filteredProviderCatalogReadyRef.current = true;
          setProviderCatalogStatus("ready");
        }
        return catalogs;
      })
      .catch(() => {
        if (generation === filteredProviderCatalogGenerationRef.current) {
          setProviderCatalogStatus("error");
        }
        return seededProviderCatalogs;
      })
      .finally(() => {
        if (filteredProviderCatalogRequestRef.current?.generation === generation) {
          filteredProviderCatalogRequestRef.current = null;
        }
      });
    filteredProviderCatalogRequestRef.current = { generation, promise: request };
    return request;
  }, [providerCatalogs, refreshProviderCatalogs]);

  const refreshProviderRegionPolicies = useCallback((options: { force?: boolean } = {}) => {
    if (!options.force && providerPolicyReadyRef.current) {
      return Promise.resolve(Object.values(providerRegionPolicies));
    }
    if (providerPolicyRequestRef.current) {
      return providerPolicyRequestRef.current;
    }
    setProviderRegionPolicyStatus("loading");
    setProviderRegionPolicyMessage("");
    const request = Promise.all([
      apiClient.sketchRegionPolicies(),
      refreshProviderCatalogs({ includeBlocked: true })
    ])
      .then(([policyResponse, catalogs]) => {
        setProviderRegionPolicies(Object.fromEntries(policyResponse.policies.map((policy) => [policy.provider, policy])));
        setProviderRegionPolicyCatalogs((current) => ({ ...current, ...catalogs }));
        providerPolicyReadyRef.current = true;
        setProviderRegionPolicyStatus("ready");
        return policyResponse.policies;
      })
      .catch(() => {
        setProviderRegionPolicyStatus("error");
        setProviderRegionPolicyMessage("Could not load sketch region allowlists.");
        return [];
      })
      .finally(() => {
        providerPolicyRequestRef.current = null;
      });
    providerPolicyRequestRef.current = request;
    return request;
  }, [providerRegionPolicies, refreshProviderCatalogs]);

  useEffect(() => {
    if (activeView !== "workspace" || activeEngagementTab !== "infrastructure") {
      return;
    }
    void refreshFilteredProviderCatalogs().catch(() => undefined);
  }, [activeEngagementTab, activeView, refreshFilteredProviderCatalogs]);

  useEffect(() => {
    if (activeView !== "settings" || activeGlobalSettingsTab !== "cloud-providers" || !isAdministrator) {
      return;
    }
    void refreshProviderRegionPolicies().catch(() => undefined);
  }, [activeGlobalSettingsTab, activeView, isAdministrator, refreshProviderRegionPolicies]);

  const updateProviderRegionPolicy = (provider: string, regionId: string, allowed: boolean) => {
    const currentPolicy = providerRegionPolicies[provider];
    const currentAllowed = currentPolicy?.allowedRegions ?? providerCatalog(providerRegionPolicyCatalogs, provider).regionPolicy?.allowedRegions ?? [];
    const nextAllowed = allowed
      ? Array.from(new Set([...currentAllowed, regionId])).sort()
      : currentAllowed.filter((region) => region !== regionId);
    setProviderRegionPolicyStatus("saving");
    setProviderRegionPolicyMessage("");
    apiClient
      .updateSketchRegionPolicy(provider, nextAllowed)
      .then((response) => {
        setProviderRegionPolicies((current) => ({ ...current, [provider]: response.policy }));
        setProviderRegionPolicyMessage(`Updated ${provider} allowed regions.`);
        setProviderRegionPolicyStatus("ready");
        filteredProviderCatalogReadyRef.current = false;
        return refreshFilteredProviderCatalogs({ force: true });
      })
      .then(() => refreshProviderCatalogs({ includeBlocked: true }))
      .then((catalogs) => {
        setProviderRegionPolicyCatalogs((current) => ({ ...current, ...catalogs }));
      })
      .catch((error) => {
        setProviderRegionPolicyStatus("error");
        setProviderRegionPolicyMessage(error instanceof Error ? error.message : "Could not update sketch region allowlist.");
      });
  };

  const updateObserverSettingsDraft = (patch: Partial<Pick<ObserverSettings, "enabled" | "provider" | "region" | "size" | "mode" | "scheduleWeekdays" | "scheduleTimeUtc" | "checkFamilies" | "portScanProfiles">>) => {
    setObserverSettings((current) => {
      if (!current) {
        return current;
      }
      const nextProvider = patch.provider ?? current.provider;
      const nextRegion = patch.region ?? (patch.provider ? providerDefaults(providerCatalogs, nextProvider).region : current.region);
      const nextSize = patch.size ?? (patch.provider || patch.region ? sizeForRegion(providerCatalogs, nextProvider, nextRegion, current.size) : current.size);
      return {
        ...current,
        enabled: patch.enabled ?? current.enabled,
        provider: nextProvider,
        region: nextRegion,
        size: nextSize,
        mode: patch.mode ?? current.mode,
        scheduleWeekdays: patch.scheduleWeekdays ?? current.scheduleWeekdays,
        scheduleTimeUtc: patch.scheduleTimeUtc ?? current.scheduleTimeUtc,
        checkFamilies: patch.checkFamilies ?? current.checkFamilies,
        portScanProfiles: patch.portScanProfiles ?? current.portScanProfiles
      };
    });
  };

  const saveObserverSettings = () => {
    if (!selectedEngagementId || !observerSettings) {
      return;
    }
    const forbiddenTcpPorts = observerForbiddenPortsInput
      .split(/[,\s]+/)
      .map((port) => port.trim())
      .filter(Boolean);
    setObserverCheckAction((current) => ({
      ...current,
      status: "saving",
      message: "Saving Inspector settings."
    }));
    apiClient
      .updateInspectorSettings(selectedEngagementId, {
        enabled: observerSettings.enabled,
        provider: observerSettings.provider,
        region: observerSettings.region,
        size: observerSettings.size,
        mode: observerSettings.mode,
        scheduleWeekdays: observerSettings.scheduleWeekdays,
        scheduleTimeUtc: observerSettings.scheduleTimeUtc,
        checkFamilies: observerSettings.checkFamilies,
        forbiddenTcpPorts,
        portScanProfiles: observerSettings.portScanProfiles
      })
      .then((response) => {
        setObserverSettings(response.settings);
        setObserverForbiddenPortsInput(response.settings.forbiddenTcpPorts.join(", "));
        setObserverCheckAction((current) => ({
          ...current,
          status: "ready",
          message: "Inspector settings saved."
        }));
      })
      .catch((error) => {
        setObserverCheckAction((current) => ({
          ...current,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not save Inspector settings.")
        }));
      });
  };

  const runObserverCheck = () => {
    if (!selectedEngagementId || !observerSettings) {
      return;
    }
    setObserverCheckAction((current) => ({
      ...current,
      status: "running",
      message: "Starting Inspector inspection.",
      job: null
    }));
    apiClient
      .runInspection(selectedEngagementId, "manual")
      .then((response) => {
        const running = ["queued", "running"].includes(response.job.status);
        setObserverCheckAction((current) => ({
          ...current,
          status: running ? "running" : response.job.status === "succeeded" ? "ready" : "error",
          message: running ? observerJobProgressMessage(response.job) : `Inspection returned ${response.status ?? response.job.status}.`,
          job: response.job
        }));
        setData((current) => ({ ...current, jobs: upsertJobSummary(current.jobs, response.job) }));
        if (!running) {
          void refreshInspectorSettingsState(selectedEngagementId).catch(() => undefined);
        }
      })
      .catch((error) => {
        setObserverCheckAction((current) => ({
          ...current,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not start inspection.")
        }));
      });
  };

  const ensureInspectorReadiness = () => {
    if (!selectedEngagementId || !observerSettings) {
      return;
    }
    setObserverCheckAction((current) => ({
      ...current,
      status: "running",
      message: "Preparing the retained Inspector host.",
      job: null
    }));
    apiClient
      .ensureInspectorReadiness(selectedEngagementId)
      .then((response) => {
        const readiness = response.readiness;
        const job = readiness.job;
        setObserverCheckAction((current) => ({
          ...current,
          status: readiness.ready ? "ready" : readiness.status === "running" ? "running" : "error",
          message: readiness.ready
            ? readiness.reused ? "Retained Inspector is ready." : "Retained Inspector is ready for public checks."
            : readiness.status === "running" ? "Inspector readiness is running."
            : "Inspector readiness failed.",
          job
        }));
        if (job) {
          setData((current) => ({ ...current, jobs: upsertJobSummary(current.jobs, job) }));
        }
        return refreshInspectorSettingsState(selectedEngagementId);
      })
      .catch((error) => {
        setObserverCheckAction((current) => ({
          ...current,
          status: "error",
          message: barraganApiErrorSummary(error, "Could not prepare the Inspector.")
        }));
      });
  };

  const createCredential = () => {
    setCredentialsStatus("saving");
    setCredentialMessage("");
    apiClient
      .createCredential(credentialForm)
      .then((response) => {
        setCredentials((current) => [response.credential, ...current.filter((credential) => credential.id !== response.credential.id)]);
        setCredentialForm({ ...credentialForm, alias: "", description: "", secret: "" });
        setCredentialMessage(`Saved ${response.credential.provider}/${response.credential.alias}`);
        setCredentialsStatus("ready");
      })
      .catch((error) => {
        setCredentialMessage(error instanceof Error ? error.message : "Credential save failed.");
        setCredentialsStatus("error");
      });
  };

  const validateCredential = (credentialId: string) => {
    setCredentialsStatus("saving");
    setCredentialMessage("");
    apiClient
      .validateCredential(credentialId)
      .then((response) => {
        const credential = response.validation.credential;
        setCredentialMessage(
          response.validation.decryptable
            ? `${credential.provider}/${credential.alias} decrypts with the configured master key.`
            : `${credential.provider}/${credential.alias} cannot decrypt with the configured master key.`
        );
        setCredentialsStatus("ready");
      })
      .catch((error) => {
        setCredentialMessage(error instanceof Error ? error.message : "Credential validation failed.");
        setCredentialsStatus("error");
      });
  };

  const setDefaultCredential = (credentialId: string) => {
    setCredentialsStatus("saving");
    setCredentialMessage("");
    apiClient
      .setDefaultCredential(credentialId)
      .then((response) => {
        setCredentials((current) =>
          current.map((credential) => ({
            ...credential,
            isDefault: credential.provider === response.credential.provider
              ? credential.id === response.credential.id
              : credential.isDefault
          }))
        );
        setCredentialMessage(`Default ${response.credential.provider} credential set to ${response.credential.alias}`);
        setCredentialsStatus("ready");
      })
      .catch((error) => {
        setCredentialMessage(error instanceof Error ? error.message : "Default credential update failed.");
        setCredentialsStatus("error");
      });
  };

  const rotateCredential = (credential: CredentialSummary) => {
    if (!credentialForm.secret) {
      setCredentialMessage("Enter the replacement secret before rotating.");
      return;
    }
    setCredentialsStatus("saving");
    setCredentialMessage("");
    apiClient
      .rotateCredential(credential.id, {
        description: credentialForm.description || credential.description,
        secret: credentialForm.secret
      })
      .then((response) => {
        setCredentials((current) =>
          current.map((candidate) => (candidate.id === response.credential.id ? response.credential : candidate))
        );
        setCredentialForm({ provider: credential.provider, alias: credential.alias, description: response.credential.description, secret: "" });
        setCredentialMessage(`Rotated ${response.credential.provider}/${response.credential.alias}`);
        setCredentialsStatus("ready");
      })
      .catch((error) => {
        setCredentialMessage(error instanceof Error ? error.message : "Credential rotation failed.");
        setCredentialsStatus("error");
      });
  };

  const disableCredential = (credentialId: string) => {
    setCredentialsStatus("saving");
    setCredentialMessage("");
    apiClient
      .deleteCredential(credentialId)
      .then((response) => {
        setCredentials((current) =>
          current.map((candidate) => (candidate.id === response.credential.id ? response.credential : candidate))
        );
        setCredentialMessage(`Disabled ${response.credential.provider}/${response.credential.alias}`);
        setCredentialsStatus("ready");
      })
      .catch((error) => {
        setCredentialMessage(error instanceof Error ? error.message : "Credential disable failed.");
        setCredentialsStatus("error");
      });
  };

  const runDigitalOceanSketchPreflight = () => {
    setDigitalOceanPreflightAction({
      status: "running",
      message: "Checking DigitalOcean sketch readiness.",
      result: null
    });
    apiClient
      .digitalOceanSketchPreflight()
      .then((response) => {
        setDigitalOceanPreflightAction({
          status: response.preflight.ready ? "ready" : "error",
          message: response.preflight.ready
            ? "DigitalOcean sketch preflight passed."
            : "DigitalOcean sketch preflight is not ready.",
          result: response.preflight
        });
      })
      .catch((error) => {
        const preflight = error instanceof BarraganApiError
          ? recordValue(error.body).preflight as SketchProviderPreflight | undefined
          : undefined;
        setDigitalOceanPreflightAction({
          status: "error",
          message: preflight ? "DigitalOcean sketch preflight is not ready." : "DigitalOcean sketch preflight failed.",
          result: preflight ?? null
        });
      });
  };

  const runDigitalOceanProviderSmokeValidation = () => {
    const confirmation = digitalOceanProviderSmokeAction.confirmation;
    setDigitalOceanProviderSmokeAction((current) => ({
      ...current,
      status: "running",
      message: "Starting guarded DigitalOcean provider-smoke validation.",
      job: null
    }));
    apiClient
      .startBarraganTestingDigitalOceanSketchValidationRun({
        confirmCreateDestroy: confirmation,
        requestedBy: "operator"
      })
      .then((response) => {
        setDigitalOceanProviderSmokeAction((current) => ({
          ...current,
          status: response.job.status === "failed" ? "error" : "ready",
          message: "DigitalOcean provider-smoke validation job started.",
          job: response.job
        }));
      })
      .catch((error) => {
        setDigitalOceanProviderSmokeAction((current) => ({
          ...current,
          status: "error",
          message: error instanceof Error ? error.message : "DigitalOcean provider-smoke validation failed.",
          job: null
        }));
      });
  };

  const generateSketchSshKey = () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchSshKeyStatus("saving");
    apiClient
      .generateEngagementSketchSshKey(selectedEngagementId)
      .then((response) => {
        setSketchSshKey(response.key);
        setSketchSshKeyStatus("ready");
      })
      .catch(() => {
        setSketchSshKeyStatus("error");
      });
  };

  const downloadSketchSshKey = () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchSshKeyStatus("loading");
    apiClient
      .engagementSketchSshKeyMaterial(selectedEngagementId)
      .then((response) => {
        setSketchSshKey(response.keyMaterial.key);
        downloadTextFile(response.keyMaterial.key.privateKeyName, response.keyMaterial.privateKey);
        downloadTextFile(response.keyMaterial.key.publicKeyName, response.keyMaterial.publicKey);
        setSketchSshKeyStatus("downloaded");
      })
      .catch(() => {
        setSketchSshKeyStatus("error");
      });
  };

  const previewSketchSshKeyRotation = () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchSshKeyRotationAction((current) => ({ ...current, status: "running", message: "" }));
    apiClient
      .previewEngagementSketchSshKeyRotation(selectedEngagementId)
      .then((response) => {
        setSketchSshKeyRotationAction((current) => ({
          ...current,
          status: "ready",
          message: response.rotation.requiresRepair
            ? "Rotation is blocked until affected sketch chains are reprovisioned or repaired through the approved jump path."
            : "Rotation is ready. Type the confirmation token to generate a new engagement sketch key.",
          preview: response.rotation
        }));
      })
      .catch((error) => {
        setSketchSshKeyRotationAction((current) => ({
          ...current,
          status: "error",
          message: error instanceof Error ? error.message : "Rotation preview failed."
        }));
      });
  };

  const rotateSketchSshKey = () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchSshKeyRotationAction((current) => ({ ...current, status: "running", message: "" }));
    apiClient
      .rotateEngagementSketchSshKey(selectedEngagementId, sketchSshKeyRotationAction.confirmation)
      .then((response) => {
        setSketchSshKey(response.key);
        setSketchSshKeyStatus("ready");
        setSketchSshKeyRotationAction((current) => ({
          ...current,
          status: "ready",
          message: "Sketch SSH key rotated. Future sketch deployments and outbound channel applies will use the new key.",
          preview: response.rotation,
          previousFingerprint: response.previousFingerprint
        }));
      })
      .catch((error) => {
        const rotation =
          error instanceof BarraganApiError &&
          typeof error.body === "object" &&
          error.body !== null &&
          "rotation" in error.body
            ? ((error.body as { rotation?: SketchSshKeyRotationPlan }).rotation ?? null)
            : null;
        setSketchSshKeyRotationAction((current) => ({
          ...current,
          status: "error",
          message: error instanceof Error ? error.message : "Sketch SSH key rotation failed.",
          preview: rotation ?? current.preview
        }));
      });
  };

  const previewSketchSshKeyRemoval = () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchSshKeyRemovalAction((current) => ({ ...current, status: "running", message: "" }));
    apiClient
      .previewEngagementSketchSshKeyRemoval(selectedEngagementId)
      .then((response) => {
        setSketchSshKeyRemovalAction((current) => ({
          ...current,
          status: "ready",
          message: response.removal.requiresTeardown
            ? "Removal is blocked until recorded infrastructure is torn down."
            : "Removal is ready. Type the confirmation token to delete Barragan's encrypted sketch key material.",
          preview: response.removal
        }));
      })
      .catch((error) => {
        setSketchSshKeyRemovalAction((current) => ({
          ...current,
          status: "error",
          message: error instanceof Error ? error.message : "Removal preview failed."
        }));
      });
  };

  const removeSketchSshKey = () => {
    if (!selectedEngagementId) {
      return;
    }
    setSketchSshKeyRemovalAction((current) => ({ ...current, status: "running", message: "" }));
    apiClient
      .removeEngagementSketchSshKey(selectedEngagementId, sketchSshKeyRemovalAction.confirmation)
      .then((response) => {
        setSketchSshKey(null);
        setSketchSshKeyStatus("idle");
        setSketchSshKeyRemovalAction((current) => ({
          ...current,
          status: "ready",
          message: response.removedKey
            ? "Encrypted sketch SSH key material removed. Generate a new key before deploying sketch again."
            : "No encrypted sketch SSH key material was stored for this engagement.",
          preview: response.removal,
          removedFingerprint: response.removal.removedFingerprint ?? ""
        }));
      })
      .catch((error) => {
        const removal =
          error instanceof BarraganApiError &&
          typeof error.body === "object" &&
          error.body !== null &&
          "removal" in error.body
            ? ((error.body as { removal?: SketchSshKeyRemovalPlan }).removal ?? null)
            : null;
        setSketchSshKeyRemovalAction((current) => ({
          ...current,
          status: "error",
          message: error instanceof Error ? error.message : "Sketch SSH key removal failed.",
          preview: removal ?? current.preview
        }));
      });
  };

  const beginTestDeploymentTeardown = () => {
    if (!testDeployRunJob) {
      return;
    }
    setTestDeployTeardownStatus("confirming");
    setTestDeployTeardownConfirmation("");
    setEngagementTeardownPreview(null);
    setEngagementTeardownPreviewStatus("loading");
    apiClient
      .barraganTestingPilotStandardRtiTeardownPreview(testDeployRunJob.id)
      .then((response) => {
        setEngagementTeardownPreview(response.teardown);
        setEngagementTeardownPreviewStatus("ready");
      })
      .catch(() => setEngagementTeardownPreviewStatus("error"));
  };

  const teardownTestDeploymentRun = () => {
    if (!testDeployRunJob) {
      return;
    }
    if (!engagementTeardownPreview || testDeployTeardownConfirmation !== engagementTeardownPreview.confirmationPhrase) {
      setTestDeployTeardownStatus("confirming");
      return;
    }
    setTestDeployTeardownStatus("running");
    setTestDeployRunStatus("running");
    setTeardownRequestState("pending");
    setInfrastructureConsoleOpen(true);
    apiClient
      .teardownBarraganTestingPilotStandardRtiRun(testDeployRunJob.id, {
        confirmation: testDeployTeardownConfirmation,
        snapshotId: engagementTeardownPreview.snapshotId
      })
      .then((response) => {
        const expectedCoreId = isEngagementTeardownAction(testDeployRunJob.action) ? testDeployRunJob.input.coreJobId : testDeployRunJob.id;
        if (response.job.action === "provider_keyed_mixed_published_cleanup" && (
          jobEngagementId(response.job) !== jobEngagementId(testDeployRunJob) || response.job.input.coreJobId !== expectedCoreId ||
          (["queued", "running"].includes(response.job.status) && !isRecoverableEngagementTeardownJob(response.job)))) {
          throw new Error("Teardown acknowledgement does not identify this deployment");
        }
        setTeardownRequestState("idle");
        const jobRunning = ["queued", "running"].includes(response.job.status);
        if (jobRunning && isEngagementTeardownAction(response.job.action)) {
          activeTeardownParentRef.current = { engagementId: jobEngagementId(response.job) ?? "", id: response.job.id };
        }
        setTestDeployRunJob(response.job);
        setTestDeployRunStatus(statusFromPilotJob(response.job));
        setTestDeployTeardownStatus(jobRunning ? "running" : "idle");
        if (!jobRunning) {
          setTestDeployTeardownConfirmation("");
          setEngagementTeardownPreview(null);
        }
      })
      .catch(() => {
        setTeardownRequestState("unconfirmed");
        setTestDeployRunStatus("error");
        setTestDeployTeardownStatus("idle");
      });
  };

  useEffect(() => {
    const jobId = testDeployRunJob?.id;
    if (!jobId || !["queued", "running"].includes(testDeployRunJob.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .barraganTestingPilotStandardRtiRun(jobId)
        .then((response) => {
          if (!cancelled) {
            if (activeTeardownParentRef.current?.id === response.job.id && !["queued", "running"].includes(response.job.status)) {
              activeTeardownParentRef.current = null;
            }
            setTestDeployRunJob(response.job);
            setTestDeployRunStatus(statusFromPilotJob(response.job));
            if (testDeployTeardownStatus === "running" && !["queued", "running"].includes(response.job.status)) {
              setTestDeployTeardownStatus("idle");
              setTestDeployTeardownConfirmation("");
              setEngagementTeardownPreview(null);
              void refreshSketchInfrastructureState();
            }
          }
        })
        .catch(() => {
          if (!cancelled) {
            setTestDeployRunStatus("error");
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [testDeployRunJob?.id, testDeployRunJob?.status, testDeployTeardownStatus]);

  useEffect(() => {
    const coreJob = testDeployRunJob;
    const coreJobId = coreJob?.id ?? "";
    const snapshotChainIds = Array.isArray(coreJob?.input.pendingSketchChainIds)
      ? coreJob.input.pendingSketchChainIds.map(String).filter(Boolean)
      : [];
    const eligible =
      Boolean(selectedEngagementId) &&
      coreJob?.status === "succeeded" &&
      coreJob.input.postCoreSketchContinuationEligible === true &&
      snapshotChainIds.length > 0;
    if (!eligible || !selectedEngagementId) {
      return;
    }

    const snapshotChains = snapshotChainIds
      .map((chainId) => sketchChainRecords.find((chain) => chain.chainId === chainId))
      .filter((chain): chain is SketchChainRecord => Boolean(chain));
    const terminalStatuses = new Set(["deployed", "failed", "destroyed", "aborted", "stopped"]);
    if (
      snapshotChains.length === snapshotChainIds.length &&
      snapshotChains.every(
        (chain) =>
          terminalStatuses.has(chain.status) ||
          Boolean(chain.deployJobId && sketchDeploymentJobs.some((job) => job.id === chain.deployJobId))
      )
    ) {
      return;
    }

    let cancelled = false;
    let interval: number | undefined;
    const refresh = async () => {
      const attempt = (postCoreSketchObserverAttemptsRef.current[coreJobId] ?? 0) + 1;
      postCoreSketchObserverAttemptsRef.current[coreJobId] = attempt;
      if (attempt > 150) {
        if (interval !== undefined) {
          window.clearInterval(interval);
        }
        return;
      }
      try {
        const response = await apiClient.engagementSketchChains(selectedEngagementId);
        if (cancelled) {
          return;
        }
        const chains = response.sketchChains ?? [];
        setSketchChainRecords(chains);
        setSketchChainRecordsStatus("ready");
        const observed = chains.filter((chain) => snapshotChainIds.includes(chain.chainId));
        const jobIds = Array.from(new Set(observed.map((chain) => chain.deployJobId).filter(Boolean)));
        if (jobIds.length) {
          const jobResponses = await Promise.all(jobIds.map((jobId) => apiClient.job(jobId)));
          if (cancelled) {
            return;
          }
          const jobs = jobResponses.map((jobResponse) => jobResponse.job);
          setSketchDeploymentJobs((current) => jobs.reduce(upsertJobDetail, current));
          const latestJob = jobs[jobs.length - 1] ?? null;
          if (latestJob) {
            setLinodeSketchRunJob(latestJob);
            setLinodeSketchRunStatus(statusFromPilotJob(latestJob));
          }
          jobs
            .filter((job) => !["queued", "running"].includes(job.status))
            .forEach((job) => void refreshSketchChainFromJob(job));
        }
        if (
          observed.length === snapshotChainIds.length &&
          observed.every((chain) => terminalStatuses.has(chain.status)) &&
          interval !== undefined
        ) {
          window.clearInterval(interval);
        }
      } catch {
        // This observer is read-only and best effort. Existing manual refresh
        // remains available without turning a transient GET failure into a mutation.
      }
    };

    void refresh();
    interval = window.setInterval(() => void refresh(), 2000);
    return () => {
      cancelled = true;
      if (interval !== undefined) {
        window.clearInterval(interval);
      }
    };
  }, [
    selectedEngagementId,
    testDeployRunJob?.id,
    testDeployRunJob?.status,
    testDeployRunJob?.input.postCoreSketchContinuationEligible,
    JSON.stringify(testDeployRunJob?.input.pendingSketchChainIds ?? []),
    sketchChainRecords.map((chain) => `${chain.chainId}:${chain.status}:${chain.deployJobId}`).join("|"),
    sketchDeploymentJobs.map((job) => `${job.id}:${job.status}`).join("|")
  ]);

  const keyedPublicationRefreshPending = selectedEngagement?.sketchStateSchema === "provider-keyed-v2" &&
    mixedSketchPublicationPending(null, engagementOperations, selectedEngagement);
  useEffect(() => {
    if (!selectedEngagementId || activeView !== "workspace" || !keyedPublicationRefreshPending ||
        !["infrastructure", "overview", "channels", "capabilities"].includes(activeEngagementTab)) return;
    const engagementId = selectedEngagementId;
    let cancelled = false;
    let refreshing = false;
    const refresh = async () => {
      if (refreshing) return;
      refreshing = true;
      try {
        const [response, chains] = await Promise.all([
          apiClient.engagementOperations(engagementId), apiClient.engagementSketchChains(engagementId)
        ]);
        if (cancelled || response.operations.engagementId !== engagementId) return;
        setEngagementOperations(response.operations);
        setEngagementOperationsStatus("ready");
        setSketchChainRecords(chains.sketchChains ?? []);
        setSketchChainRecordsStatus("ready");
      } catch {
        // Retain the publication gate and retry after transient read failures.
      } finally {
        refreshing = false;
      }
    };
    const interval = window.setInterval(() => void refresh(), 3000);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [selectedEngagementId, activeView, activeEngagementTab, keyedPublicationRefreshPending]);

  useEffect(() => {
    const job = providerOrphanRecoveryAction.job;
    if (!job || !["queued", "running"].includes(job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(job.id)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const latestMessage = response.job.events[response.job.events.length - 1]?.message ?? "Provider recovery job updated.";
          const running = ["queued", "running"].includes(response.job.status);
          setProviderOrphanRecoveryAction((current) => ({
            ...current,
            status: running ? "running" : response.job.status === "failed" ? "error" : "ready",
            message: latestMessage,
            job: response.job
          }));
          setData((current) => ({
            ...current,
            jobs: current.jobs.map((summary) =>
              summary.id === response.job.id ? { ...summary, status: response.job.status } : summary
            )
          }));
          if (!running) {
            void Promise.all([
              loadDashboard({ live: true }),
              selectedEngagementId ? apiClient.engagementOperations(selectedEngagementId).catch(() => null) : Promise.resolve(null)
            ]).then(([_dashboard, operations]) => {
              if (cancelled) {
                return;
              }
              if (operations?.operations) {
                setEngagementOperations(operations.operations);
                setHousekeepingItemsDraft(operations.operations.housekeepingItems);
                setEngagementOperationsStatus("ready");
              }
            });
          }
        })
        .catch(() => {
          if (!cancelled) {
            setProviderOrphanRecoveryAction((current) => ({
              ...current,
              status: "error",
              message: "Could not refresh provider recovery progress."
            }));
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [providerOrphanRecoveryAction.job?.id, providerOrphanRecoveryAction.job?.status, selectedEngagementId]);

  useEffect(() => {
    const job = linodeSketchRunJob;
    if (!lifecycleConsoleOpen || lifecycleConsoleSource !== "sketch" || !job || !["queued", "running"].includes(job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(job.id)
        .then((response) => {
          if (cancelled) {
            return;
          }
          setLinodeSketchRunJob(response.job);
          setLinodeSketchRunStatus(statusFromPilotJob(response.job));
          setSketchDeploymentJobs((current) => upsertJobDetail(current, response.job));
          void refreshSketchChainFromJob(response.job);
        })
        .catch(() => {
          if (!cancelled) {
            setLinodeSketchRunStatus("error");
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [lifecycleConsoleOpen, lifecycleConsoleSource, linodeSketchRunJob?.id, linodeSketchRunJob?.status]);

  const lifecycleConsoleJob = lifecycleConsoleSource === "provider" ? providerOrphanRecoveryAction.job : linodeSketchRunJob;
  const lifecycleConsoleCopy = lifecycleConsoleSource === "provider"
    ? { title: "Provider recovery progress", emptyText: "Starting provider recovery teardown." }
    : sketchLifecycleConsoleCopy(lifecycleConsoleJob);
  const lifecycleConsoleTitle = lifecycleConsoleCopy.title;
  const lifecycleConsoleEmptyText = lifecycleConsoleCopy.emptyText;
  const lifecycleConsoleLog = jobConsoleText(
    lifecycleConsoleJob,
    lifecycleConsoleEmptyText,
    lifecycleConsoleSource === "sketch" ? sketchConsoleEventText : undefined
  );

  return (
    <div className="app-shell" data-theme={theme}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">B</span>
          <div>
            <h1>Barragan</h1>
            <p>RTI Control Plane</p>
          </div>
        </div>
        <section className="sidebar-workspace" aria-label="Active engagement workspace">
          <label className="workspace-select">
            <span>Active engagement</span>
            <div>
              <select
                aria-label="Active engagement"
                onChange={(event) => selectEngagement(event.target.value || null)}
                value={selectedEngagement?.id ?? ""}
              >
                {activeEngagements.length === 0 ? (
                  <option value="">No active engagements</option>
                ) : null}
                {activeEngagements.map((engagement) => (
                  <option key={engagement.id} value={engagement.id}>
                    {engagement.name}
                  </option>
                ))}
              </select>
              <ChevronDown aria-hidden="true" size={16} />
            </div>
          </label>
        </section>
        <nav className="nav workspace-nav" aria-label="Engagement workspace sections">
          {engagementTabs.map((tab) => {
            const Icon = tab.icon;
            const active = activeView === "workspace" && activeEngagementTab === tab.key;
            return (
              <button
                className={active ? "nav-item active" : "nav-item"}
                key={tab.key}
                onClick={() => {
                  setActiveView("workspace");
                  setActiveEngagementTab(tab.key);
                }}
                type="button"
              >
                <Icon aria-hidden="true" size={18} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
        <nav className="nav global-nav" aria-label="Global">
          {globalNavItems.filter((item) => isAdministrator || item.key !== "team").map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={activeView === item.key ? "nav-item active" : "nav-item"}
                key={item.key}
                onClick={() => {
                  if (item.key === "dashboard" && activeView !== "dashboard") setDashboardStatus("loading");
                  setActiveView(item.key);
                  if (item.key === "settings") setActiveGlobalSettingsTab("user");
                }}
                type="button"
              >
                <Icon aria-hidden="true" size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">{topbarEyebrow}</p>
            <h2>{topbarTitle}</h2>
          </div>
          <div className="topbar-actions">
            <div className="theme-switcher" aria-label="Theme">
              <button
                aria-pressed={theme === "light"}
                className={theme === "light" ? "active" : ""}
                onClick={() => setTheme("light")}
                title="Use light theme"
                type="button"
              >
                <Sun aria-hidden="true" size={16} />
                <span>Light</span>
              </button>
              <button
                aria-pressed={theme === "dark"}
                className={theme === "dark" ? "active" : ""}
                onClick={() => setTheme("dark")}
                title="Use dark theme"
                type="button"
              >
                <Moon aria-hidden="true" size={16} />
                <span>Dark</span>
              </button>
            </div>
            <span className={`status ${status}`}>{status}</span>
          </div>
        </header>

        {readOnly ? <p className="permission-notice" role="status">Limited access: operational controls are disabled for this account.</p> : null}
        {status === "error" ? (
          <section className="empty-state">
            <h3>API unavailable</h3>
            <p>Check the Barragan FastAPI service and refresh this view.</p>
          </section>
        ) : (
          <fieldset className="permission-boundary" disabled={readOnly && activeView !== "settings"}>
          <Content
            activeView={activeView}
            activeGlobalSettingsTab={activeGlobalSettingsTab}
            currentUser={currentUser}
            isAdministrator={isAdministrator}
            onChangePassword={onChangePassword}
            onSignOut={onSignOut}
            onSignOutAll={onSignOutAll}
            activeEngagementTab={activeEngagementTab}
            credentialForm={credentialForm}
            credentialMessage={credentialMessage}
            credentials={credentials}
            credentialsStatus={credentialsStatus}
            digitalOceanPreflightAction={digitalOceanPreflightAction}
            digitalOceanProviderSmokeAction={digitalOceanProviderSmokeAction}
            engagementWorkflowRevision={engagementWorkflowRevision}
            engagementWorkflowStatus={engagementWorkflowStatus}
            engagementOperations={engagementOperations}
            engagementOperationsStatus={engagementOperationsStatus}
            engagementWorkspace={engagementWorkspace}
            engagementWorkspaceStatus={engagementWorkspaceStatus}
            backflipsServiceAction={backflipsServiceAction}
            desktopServiceAction={desktopServiceAction}
            genericServiceAction={genericServiceAction}
            genericServiceForm={genericServiceForm}
            webStaticServiceAction={webStaticServiceAction}
            webStaticServiceForm={webStaticServiceForm}
            webStaticServiceRemovalAction={webStaticServiceRemovalAction}
            guidedBackflipEnabled={guidedBackflipEnabled}
            guidedDeploymentInput={guidedDeploymentInput}
            guidedEngagementName={guidedEngagementName}
            guidedOperators={guidedOperators}
            guidedOperatorsList={guidedOperatorsList}
            guidedSshEnabled={guidedSshEnabled}
            housekeepingItemsDraft={housekeepingItemsDraft}
            infrastructureConsoleOpen={infrastructureConsoleOpen}
            jobsPagination={jobsPagination}
            jobsStatus={jobsStatus}
            inboundChannelAction={inboundChannelAction}
            inboundChannelDraft={inboundChannelDraft}
            linodeSketchChain={linodeSketchChain}
            linodeSketchRunJob={linodeSketchRunJob}
            linodeSketchRunStatus={linodeSketchRunStatus}
            deployableInitialSketchChains={deployableInitialSketchChains}
            sketchDeploymentJobs={sketchDeploymentJobs}
            outboundChannelAction={outboundChannelAction}
            outboundChannelDraft={outboundChannelDraft}
            sketchSshKey={sketchSshKey}
            sketchSshKeyStatus={sketchSshKeyStatus}
            sketchSshKeyRemovalAction={sketchSshKeyRemovalAction}
            sketchSshKeyRotationAction={sketchSshKeyRotationAction}
            sketchChainRecords={sketchChainRecords}
            sketchChainRecordsStatus={sketchChainRecordsStatus}
            sketchChainMessage={sketchChainMessage}
            sketchChainCancelTarget={sketchChainCancelTarget}
            sketchChainCancelConfirmation={sketchChainCancelConfirmation}
            sketchChainPowerConfirmations={sketchChainPowerConfirmations}
            sketchChainTeardownTarget={sketchChainTeardownTarget}
            sketchChainTeardownConfirmation={sketchChainTeardownConfirmation}
            sketchIntent={sketchIntent}
            observerSettings={observerSettings}
            observerForbiddenPortsInput={observerForbiddenPortsInput}
            observerCheckAction={observerCheckAction}
            data={data}
            onArchiveEngagement={archiveMetadataEngagement}
            onCompileSelectedRevision={compileSelectedRevision}
            onCreateEngagement={createMetadataEngagement}
            onCreateCredential={createCredential}
            onDeleteEngagement={deleteMetadataEngagement}
            onReconcileEngagement={reconcileMetadataEngagement}
            onDisableCredential={disableCredential}
            onRunDigitalOceanSketchPreflight={runDigitalOceanSketchPreflight}
            onRunDigitalOceanProviderSmokeValidation={runDigitalOceanProviderSmokeValidation}
            onEditEngagement={updateMetadataEngagement}
            onRefreshCredentials={refreshCredentials}
            onRefreshProviderRegionPolicies={() => refreshProviderRegionPolicies({ force: true })}
            onEnsureProviderCatalogs={refreshFilteredProviderCatalogs}
            onUpdateProviderRegionPolicy={updateProviderRegionPolicy}
            onUpdateObserverSettingsDraft={updateObserverSettingsDraft}
            onSaveObserverSettings={saveObserverSettings}
            onEnsureInspectorReadiness={ensureInspectorReadiness}
            onRunObserverCheck={runObserverCheck}
            onInspectorCleanupComplete={() => selectedEngagementId ? refreshInspectorSettingsState(selectedEngagementId) : Promise.resolve(null)}
            onRefreshLinodeSketchRun={refreshLinodeSketchRun}
            onLoadSelectedRevisions={loadSelectedRevisions}
            onLoadJobsPage={loadJobsPage}
            onOpenEngagementWorkspace={(engagementId) => {
              selectEngagement(engagementId);
              setActiveEngagementTab("overview");
            }}
            onPrepareEngagementWorkspace={prepareDurableWorkspace}
            onRunTestDeployment={runTestDeployment}
            onRecordChannels={recordChannels}
            onRecoverProviderOrphan={recoverProviderOrphan}
            onOpenLifecycleConsole={(source) => {
              setLifecycleConsoleSource(source);
              setLifecycleConsoleOpen(true);
            }}
            onRefreshDashboardProviderInventory={refreshDashboardProviderInventory}
            onSetProviderOrphanTeardownConfirmation={setProviderOrphanTeardownConfirmation}
            onCreateInboundChannel={createInboundChannel}
            onEditInboundChannel={editInboundChannel}
            onDisableInboundChannel={disableInboundChannel}
            onRemoveInboundChannel={removeInboundChannel}
            onRecoverInboundChannel={recoverInboundChannel}
            onSaveHousekeepingItems={saveHousekeepingItems}
            onPreviewInboundChannelApply={previewInboundChannelApply}
            onApplyInboundChannel={applyInboundChannel}
            onValidateInboundChannel={validateInboundChannel}
            onUpdateInboundChannelConfirmation={updateInboundChannelConfirmation}
            onRefreshEngagementOperations={refreshEngagementOperations}
            onPreviewOutboundChannelApply={previewOutboundChannelApply}
            onApplyOutboundChannel={applyOutboundChannel}
            onValidateOutboundChannel={validateOutboundChannel}
            onUpdateOutboundChannelConfirmation={updateOutboundChannelConfirmation}
            onPreviewBackflipsServiceApply={previewBackflipsServiceApply}
            onApplyBackflipsService={applyBackflipsService}
            onUpdateBackflipsServiceAction={updateBackflipsServiceAction}
            backflipsConsoleOpen={backflipsConsoleOpen}
            backflipsConsoleCopied={backflipsConsoleCopied}
            setBackflipsConsoleOpen={setBackflipsConsoleOpen}
            setBackflipsConsoleCopied={setBackflipsConsoleCopied}
            onApplyDesktopService={applyDesktopService}
            onPreviewWebStaticServiceApply={previewWebStaticServiceApply}
            onApplyWebStaticService={applyWebStaticService}
            onRestoreWebStaticService={restoreWebStaticService}
            onPreviewWebStaticServiceRemove={previewWebStaticServiceRemove}
            onApplyWebStaticServiceRemove={applyWebStaticServiceRemove}
            onUpdateWebStaticServiceForm={updateWebStaticServiceForm}
            onResetWebStaticServiceAction={resetWebStaticServiceAction}
            onUpdateWebStaticServiceRemovalAction={setWebStaticServiceRemovalAction}
            onSaveGenericService={saveGenericService}
            onDisableGenericService={disableGenericService}
            onRestoreGenericService={restoreGenericService}
            onRemoveGenericService={removeGenericService}
            onUpdateGenericServiceForm={updateGenericServiceForm}
            onUpdateGenericServiceAction={setGenericServiceAction}
            onRefreshTestDeploymentRun={refreshTestDeploymentRun}
            onRenderSelectedRevision={renderSelectedRevision}
            onTeardownTestDeploymentRun={teardownTestDeploymentRun}
            onBeginTestDeploymentTeardown={beginTestDeploymentTeardown}
            onRotateCredential={rotateCredential}
            onResumePilotRunFromJob={resumePilotRunFromJob}
            onSelectJob={loadJobDetail}
            onSetDefaultCredential={setDefaultCredential}
            onValidateCredential={validateCredential}
            onGenerateSketchSshKey={generateSketchSshKey}
            onDownloadSketchSshKey={downloadSketchSshKey}
            onPreviewSketchSshKeyRemoval={previewSketchSshKeyRemoval}
            onPreviewSketchSshKeyRotation={previewSketchSshKeyRotation}
            onRemoveSketchSshKey={removeSketchSshKey}
            onRotateSketchSshKey={rotateSketchSshKey}
            onCreateReplacementSketchChain={createReplacementSketchChain}
            onDeploySketchChainRecord={deploySketchChainRecord}
            onCancelSketchChainRecord={cancelSketchChainRecord}
            onMarkSketchChainBurned={markSketchChainBurned}
            onUpdateSketchChainRecord={updateSketchChainRecord}
            onTeardownSketchChainRecord={teardownSketchChainRecord}
            onStartSketchChainRecord={startSketchChainRecord}
            onStopSketchChainRecord={stopSketchChainRecord}
            onUpdateSketchChainPowerConfirmation={updateSketchChainPowerConfirmation}
            onRetireSketchChainFinalEdge={retireSketchChainFinalEdge}
            onReplaceSketchChainFinalEdge={replaceSketchChainFinalEdge}
            sketchEdgeTransitionConfirmations={sketchEdgeTransitionConfirmations}
            sketchEdgeReplacementRegions={sketchEdgeReplacementRegions}
            setSketchEdgeTransitionConfirmations={setSketchEdgeTransitionConfirmations}
            setSketchEdgeReplacementRegions={setSketchEdgeReplacementRegions}
            corePlan={displayedCorePlan}
            corePlanStatus={displayedCorePlanStatus}
            providerCatalogs={providerCatalogs}
            providerCatalogStatus={providerCatalogStatus}
            providerRegionPolicies={providerRegionPolicies}
            providerRegionPolicyCatalogs={providerRegionPolicyCatalogs}
            providerRegionPolicyMessage={providerRegionPolicyMessage}
            providerRegionPolicyStatus={providerRegionPolicyStatus}
            revisionHistory={revisionHistory}
            revisionHistoryStatus={revisionHistoryStatus}
            revisionRenderResult={revisionRenderResult}
            revisionRenderStatus={revisionRenderStatus}
            selectedEngagement={selectedEngagement}
            selectedEngagementId={selectedEngagementId}
            selectedInfrastructureTemplate={selectedInfrastructureTemplate}
            selectedInfrastructureTemplateId={selectedInfrastructureTemplateId}
            selectedJobDetail={selectedJobDetail}
            selectedJobDetailStatus={selectedJobDetailStatus}
            selectedRevisionId={selectedRevisionId}
            setGuidedBackflipEnabled={setGuidedBackflipEnabled}
            setGuidedElkEnabled={(value) => { editorEditEpochRef.current.elk += 1; editorDirtyRef.current.elk = true; setGuidedElkEnabled(value); }}
            setGuidedEngagementName={setGuidedEngagementName}
            setGuidedOperators={setGuidedOperators}
            setGuidedSshEnabled={setGuidedSshEnabled}
            setSelectedInfrastructureTemplateId={(value) => { editorEditEpochRef.current.template += 1; editorDirtyRef.current.template = true; setSelectedInfrastructureTemplateId(value); }}
            selectedDeploymentTargetName={selectedDeploymentTargetName}
            setSelectedDeploymentTargetName={(value) => { editorEditEpochRef.current.target += 1; editorDirtyRef.current.target = true; setSelectedDeploymentTargetName(value); }}
            setHousekeepingItemsDraft={setHousekeepingItemsDraft}
            setInfrastructureConsoleOpen={setInfrastructureConsoleOpen}
            setInboundChannelDraft={setInboundChannelDraft}
            setOutboundChannelDraft={setOutboundChannelDraft}
            setCredentialForm={setCredentialForm}
            setDigitalOceanProviderSmokeAction={setDigitalOceanProviderSmokeAction}
            setSketchSshKeyRemovalAction={setSketchSshKeyRemovalAction}
            setSketchSshKeyRotationAction={setSketchSshKeyRotationAction}
            setSketchIntent={(value) => { editorEditEpochRef.current.sketch += 1; editorDirtyRef.current.sketch = true; setSketchIntent(value); }}
            setSketchChainCancelTarget={setSketchChainCancelTarget}
            setSketchChainCancelConfirmation={setSketchChainCancelConfirmation}
            setSketchChainTeardownTarget={setSketchChainTeardownTarget}
            setSketchChainTeardownConfirmation={setSketchChainTeardownConfirmation}
            setObserverForbiddenPortsInput={setObserverForbiddenPortsInput}
            setObserverCheckAction={setObserverCheckAction}
            setActiveEngagementTab={setActiveEngagementTab}
            setActiveGlobalSettingsTab={setActiveGlobalSettingsTab}
            setTestDeployConfirmation={setTestDeployConfirmation}
            setTestDeploySshSourceCidrs={setTestDeploySshSourceCidrs}
            setTestDeployTeardownConfirmation={setTestDeployTeardownConfirmation}
            setTestDeployTeardownStatus={setTestDeployTeardownStatus}
            setSelectedRevisionId={selectRevision}
            setSelectedEngagementId={(engagementId) => selectEngagement(engagementId)}
            stats={dashboardStats}
            dashboard={data.dashboard}
            dashboardProviderRefreshStatus={dashboardProviderRefreshStatus}
            dashboardStatus={dashboardStatus}
            providerOrphanRecoveryAction={providerOrphanRecoveryAction}
            testDeployConfirmation={testDeployConfirmation}
            testDeploySshSourceCidrs={testDeploySshSourceCidrs}
            testDeployReadiness={testDeployReadiness}
            testDeployReadinessStatus={testDeployReadinessStatus}
            testDeployResult={testDeployResult}
            testDeployRunJob={testDeployRunJob}
            teardownParentLoadStatus={teardownParentLoadStatus}
            teardownRequestPending={teardownRequestPending}
            teardownRequestUnconfirmed={teardownRequestUnconfirmed}
            testDeployRunStatus={testDeployRunStatus}
            testDeployTeardownConfirmation={testDeployTeardownConfirmation}
            testDeployTeardownStatus={testDeployTeardownStatus}
            engagementTeardownPreview={engagementTeardownPreview}
            engagementTeardownPreviewStatus={engagementTeardownPreviewStatus}
          />
          </fieldset>
        )}
        {lifecycleConsoleOpen && lifecycleConsoleJob ? (
          <div className="modal-scrim" role="presentation">
            <section className="floating-panel job-console-panel" aria-label={lifecycleConsoleTitle}>
              <div className="section-heading">
                <div>
                  <h3>{lifecycleConsoleTitle}</h3>
                  <ProgressConsolePrimaryLine
                    job={lifecycleConsoleJob}
                    summary={lifecycleConsoleJob.status === "running" ? "The job continues if this panel is closed." : `Job ${lifecycleConsoleJob.status}.`}
                  />
                </div>
                <div className="section-actions">
                  <button
                    className="secondary-action compact"
                    disabled={!navigator.clipboard}
                    onClick={() => void navigator.clipboard?.writeText(lifecycleConsoleLog)}
                    type="button"
                  >
                    <Copy aria-hidden="true" size={14} />
                    Copy log
                  </button>
                  <button className="secondary-action compact" onClick={() => setLifecycleConsoleOpen(false)} type="button">
                    Close
                  </button>
                </div>
              </div>
              <pre>{lifecycleConsoleLog}</pre>
            </section>
          </div>
        ) : null}
      </main>
    </div>
  );
}

const emptyEngagementMetadata: EngagementMetadataFormState = {
  name: "",
  owner: "example_operator",
  description: "",
  documentationUrl: "",
  jiraUrl: ""
};

const emptyTeamMemberForm: TeamMemberRequest = {
  username: "",
  displayName: "",
  email: "",
  desiredUid: null,
  defaultInfraGroups: ["redteam", "volunteer"],
  globalRoles: ["operator"]
};

type GlobalTeamPanelMode = "create" | "configure" | "import" | null;

type TeamKeyFormState = {
  keyId: string;
  memberId: string;
  label: string;
  publicKey: string;
};

type TeamImportFormState = {
  fileName: string;
  format: string;
  content: string;
  preview: TeamImportPreview | null;
  appliedMessage: string;
};

type TeamImportStep = "select" | "preview" | "apply";

function toggleListValue(values: string[], value: string) {
  return values.includes(value) ? values.filter((candidate) => candidate !== value) : [...values, value];
}

function replaceTeamMember(workspace: TeamWorkspace | null, member: TeamMember): TeamWorkspace | null {
  if (!workspace) {
    return workspace;
  }
  const exists = workspace.members.some((candidate) => candidate.id === member.id);
  return {
    ...workspace,
    members: (exists
      ? workspace.members.map((candidate) => (candidate.id === member.id ? member : candidate))
      : [...workspace.members, member]
    ).sort((left, right) => left.username.localeCompare(right.username))
  };
}

export function GlobalTeamPage() {
  const [workspace, setWorkspace] = useState<TeamWorkspace | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "saving" | "ready" | "error">("idle");
  const [message, setMessage] = useState("");
  const [panelMode, setPanelMode] = useState<GlobalTeamPanelMode>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<TeamMemberRequest>(emptyTeamMemberForm);
  const [keyForm, setKeyForm] = useState<TeamKeyFormState>({
    keyId: "",
    memberId: "",
    label: "piv",
    publicKey: ""
  });
  const [importForm, setImportForm] = useState<TeamImportFormState>({
    fileName: "",
    format: "json",
    content: "",
    preview: null,
    appliedMessage: ""
  });

  const loadTeam = () => {
    setStatus("loading");
    setMessage("");
    return apiClient
      .team()
      .then((response) => {
        setWorkspace(response);
        setStatus("ready");
        return response;
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not load global team."));
        return null;
      });
  };

  useEffect(() => {
    void loadTeam();
  }, []);

  const resetForm = () => {
    setEditingId(null);
    setForm({
      ...emptyTeamMemberForm,
      defaultInfraGroups: workspace?.defaultInfraGroups ?? ["redteam", "volunteer"]
    });
    setKeyForm({ keyId: "", memberId: "", label: "piv", publicKey: "" });
  };

  const openCreatePanel = () => {
    resetForm();
    setMessage("");
    setPanelMode("create");
  };

  const openConfigurePanel = (member: TeamMember) => {
    setEditingId(member.id);
    setForm({
      username: member.username,
      displayName: member.displayName,
      email: member.email,
      desiredUid: member.desiredUid ?? null,
      defaultInfraGroups: member.defaultInfraGroups,
      globalRoles: member.globalRoles.length ? member.globalRoles : ["operator"]
    });
    setKeyForm({ keyId: "", memberId: member.id, label: "piv", publicKey: "" });
    setMessage("");
    setPanelMode("configure");
  };

  const openImportPanel = () => {
    setImportForm({ fileName: "", format: "json", content: "", preview: null, appliedMessage: "" });
    setMessage("");
    setPanelMode("import");
  };

  const closePanel = () => {
    setPanelMode(null);
    resetForm();
    setImportForm({ fileName: "", format: "json", content: "", preview: null, appliedMessage: "" });
  };

  const saveMember = () => {
    if (!form.username.trim()) {
      return;
    }
    setStatus("saving");
    setMessage("");
    const request = editingId ? apiClient.updateTeamMember(editingId, form) : apiClient.createTeamMember(form);
    request
      .then((response) => {
        setWorkspace((current) => replaceTeamMember(current, response.member));
        setStatus("ready");
        setMessage(`${response.member.username} saved.`);
        closePanel();
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not save team member."));
      });
  };

  const deactivateMember = (member: TeamMember) => {
    setStatus("saving");
    setMessage("");
    apiClient
      .deactivateTeamMember(member.id)
      .then((response) => {
        setWorkspace((current) => replaceTeamMember(current, response.member));
        setStatus("ready");
        setMessage(`${response.member.username} deactivated.`);
        setPanelMode(null);
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not deactivate team member."));
      });
  };

  const reactivateMember = (member: TeamMember) => {
    setStatus("saving");
    setMessage("");
    apiClient
      .updateTeamMember(member.id, { status: "active" })
      .then((response) => {
        setWorkspace((current) => replaceTeamMember(current, response.member));
        setStatus("ready");
        setMessage(`${response.member.username} reactivated. Apply access changes in each engagement to restore infrastructure access.`);
        setPanelMode(null);
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not reactivate team member."));
      });
  };

  const saveSshKey = () => {
    if (!keyForm.memberId || !keyForm.publicKey.trim()) {
      return;
    }
    setStatus("saving");
    setMessage("");
    const request = keyForm.keyId
      ? apiClient.updateTeamMemberSshKey(keyForm.memberId, keyForm.keyId, { label: keyForm.label, publicKey: keyForm.publicKey })
      : apiClient.addTeamMemberSshKey(keyForm.memberId, { label: keyForm.label, publicKey: keyForm.publicKey });
    request
      .then((response) => {
        setWorkspace((current) => replaceTeamMember(current, response.member));
        setStatus("ready");
        setMessage(`SSH key ${response.sshKey.fingerprint} saved for ${response.member.username}.`);
        setKeyForm({ keyId: "", memberId: response.member.id, label: "piv", publicKey: "" });
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not add SSH public key."));
      });
  };

  const retireSshKey = (member: TeamMember, keyId: string) => {
    setStatus("saving");
    setMessage("");
    apiClient
      .retireTeamMemberSshKey(member.id, keyId)
      .then((response) => {
        setWorkspace((current) => replaceTeamMember(current, response.member));
        setStatus("ready");
        setMessage(`SSH key retired for ${response.member.username}.`);
        setKeyForm({ keyId: "", memberId: response.member.id, label: "piv", publicKey: "" });
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not retire SSH public key."));
      });
  };

  const editSshKey = (member: TeamMember, keyId: string) => {
    const key = member.sshKeys.find((candidate) => candidate.id === keyId);
    if (!key) {
      return;
    }
    setKeyForm({ keyId: key.id, memberId: member.id, label: key.label, publicKey: key.publicKey });
  };

  const handleImportFile = (file: File | null) => {
    if (!file) {
      return;
    }
    const lowerName = file.name.toLowerCase();
    const format = lowerName.endsWith(".json") ? "json" : "yml";
    file.text()
      .then((content) => setImportForm({ fileName: file.name, format, content, preview: null, appliedMessage: "" }))
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not read users file."));
      });
  };

  const resetImportFile = () => {
    setImportForm({ fileName: "", format: "json", content: "", preview: null, appliedMessage: "" });
    setMessage("");
  };

  const previewImport = () => {
    if (!importForm.content.trim()) {
      return;
    }
    setStatus("saving");
    setMessage("");
    apiClient
      .previewTeamImport({ content: importForm.content, fileName: importForm.fileName || "users import", format: importForm.format })
      .then((response) => {
        setImportForm((current) => ({ ...current, preview: response.preview, appliedMessage: "" }));
        setStatus("ready");
        setMessage("Import preview ready.");
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not preview users import."));
      });
  };

  const applyImport = () => {
    if (!importForm.content.trim() || !importForm.preview) {
      return;
    }
    setStatus("saving");
    setMessage("");
    apiClient
      .applyTeamImport({ content: importForm.content, fileName: importForm.fileName || "users import", format: importForm.format })
      .then((response) => {
        setWorkspace(response.team);
        setImportForm((current) => ({
          ...current,
          preview: response.preview,
          appliedMessage: `${response.applied.created.length} created, ${response.applied.updated.length} updated, ${response.applied.keyAdditions} SSH keys added, ${response.applied.skipped.length} skipped.`
        }));
        setStatus("ready");
        setMessage("Users import applied.");
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not apply users import."));
      });
  };

  const supportedGroups = workspace?.supportedInfraGroups ?? ["redteam", "core", "volunteer", "infra"];
  const members = workspace?.members ?? [];
  const formReady = form.username.trim().length > 0 && status !== "saving";
  const selectedMember = members.find((member) => member.id === editingId) ?? null;
  const importStep: TeamImportStep = importForm.appliedMessage ? "apply" : importForm.preview ? "preview" : "select";

  return (
    <section className="workflow-view" aria-label="Global team management">
      <div className="workflow-panel">
        <div>
          <p className="eyebrow">Global</p>
          <h3>Team</h3>
          <p>Manage reusable operator identities, SSH public keys, and default infrastructure Linux groups.</p>
        </div>
        <div className="section-actions">
          <span className={`status ${status === "error" ? "error" : "ready"}`}>{status}</span>
          <button className="primary-action compact" onClick={openCreatePanel} type="button">
            Create Member
          </button>
          <button className="secondary-action compact" onClick={openImportPanel} type="button">
            Import Users
          </button>
          <button className="secondary-action compact" onClick={() => void loadTeam()} type="button">
            Refresh
          </button>
        </div>
      </div>
      {message ? (
        <div className={status === "error" ? "inline-alert" : "inline-warning"} role="status">
          {message}
        </div>
      ) : null}

      <section className="table-panel embedded operations-table global-team-table" aria-label="Global team members">
        <TableHeader columns={["User ID", "Status", "Default Groups", "SSH Keys", "Actions"]} />
        {members.length ? (
          members.map((member) => (
            <div className="table-row engagement-row" key={member.id}>
              <span>
                <strong>{member.username}</strong>
                <small>{member.displayName || member.email || "No profile details"}</small>
                <small>{member.desiredUid != null ? `UID ${member.desiredUid}` : "UID needs reconciliation"}</small>
              </span>
              <StatusPill value={member.status} />
              <span>{member.defaultInfraGroups.join(", ") || "none"}</span>
              <span>
                <strong>{member.sshKeys.filter((key) => key.status === "active").length} active</strong>
                <small>{member.sshKeys.map((key) => `${key.label}:${key.fingerprint}`).join(", ") || "No keys"}</small>
              </span>
              <span className="row-actions">
                <button className="secondary-action compact" onClick={() => openConfigurePanel(member)} type="button">
                  Configure
                </button>
              </span>
            </div>
          ))
        ) : (
          <OperationsEmptyState message="No global team members are configured yet." />
        )}
      </section>

      {(panelMode === "create" || panelMode === "configure") ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel team-floating-panel" aria-label={panelMode === "create" ? "Create team member" : "Configure team member"}>
            <div className="section-heading">
              <div>
                <p className="eyebrow">{panelMode === "create" ? "Create" : "Configure"}</p>
                <h3>{panelMode === "create" ? "Create Member" : `Configure ${selectedMember?.username ?? "Member"}`}</h3>
                <p>Manage Barragan identity details, default infrastructure Linux groups, and SSH public keys.</p>
              </div>
              <button className="secondary-action compact" onClick={closePanel} type="button">
                Close
              </button>
            </div>
            {selectedMember ? (
              <div aria-label="Team member account status">
                <StatusPill value={selectedMember.status} />
                {selectedMember.status === "deactivated" ? (
                  <p>This member is deactivated. Adding or editing SSH keys does not reactivate the account. Reactivate Member, then apply access changes in each engagement to restore infrastructure access.</p>
                ) : null}
              </div>
            ) : null}
            <div className="form-grid team-modal-grid">
              <label>
                <span>User ID</span>
                <input
                  aria-label="Team member username"
                  onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
                  value={form.username}
                />
              </label>
              <label>
                <span>Display name</span>
                <input
                  aria-label="Team member display name"
                  onChange={(event) => setForm((current) => ({ ...current, displayName: event.target.value }))}
                  value={form.displayName ?? ""}
                />
              </label>
              <label>
                <span>Email</span>
                <input
                  aria-label="Team member email"
                  onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                  value={form.email ?? ""}
                />
              </label>
              <label>
                <span>Desired UID</span>
                <input
                  aria-label="Team member desired UID"
                  inputMode="numeric"
                  min={6000}
                  max={64999}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      desiredUid: event.target.value.trim() ? Number(event.target.value) : null
                    }))
                  }
                  type="number"
                  value={form.desiredUid ?? ""}
                />
                <small>{editingId
                  ? selectedMember?.desiredUid != null
                    ? `Leave blank to keep UID ${selectedMember.desiredUid}. Changing an existing host account requires reconciliation.`
                    : "No UID is assigned. Leave blank to preserve this record; assign a UID only after reviewed reconciliation."
                  : "Leave blank to assign a persistent UID automatically. An explicit UID must be unused and between 6000 and 64999."}</small>
              </label>
              <div className="wide-field checkbox-group" role="group" aria-label="Default infrastructure groups">
                <span>Default infrastructure groups</span>
                {supportedGroups.map((group) => (
                  <label key={`global-team-modal-group-${group}`}>
                    <input
                      checked={(form.defaultInfraGroups ?? []).includes(group)}
                      onChange={() =>
                        setForm((current) => ({
                          ...current,
                          defaultInfraGroups: toggleListValue(current.defaultInfraGroups ?? [], group)
                        }))
                      }
                      type="checkbox"
                    />
                    <span>{group}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="form-actions">
              <button className="primary-action" disabled={!formReady} onClick={saveMember} type="button">
                {panelMode === "create" ? "Create Member" : "Save Member"}
              </button>
              <button className="secondary-action" onClick={closePanel} type="button">
                Cancel
              </button>
              {panelMode === "configure" && selectedMember ? (
                selectedMember.status === "deactivated" ? (
                  <button className="secondary-action" disabled={status === "saving"} onClick={() => reactivateMember(selectedMember)} type="button">
                    Reactivate Member
                  </button>
                ) : (
                  <button className="danger-action" disabled={status === "saving"} onClick={() => deactivateMember(selectedMember)} type="button">
                    Deactivate Member
                  </button>
                )
              ) : null}
            </div>
            {panelMode === "configure" && selectedMember ? (
              <div className="team-key-section">
                <div className="section-heading">
                  <div>
                    <h3>SSH Public Keys</h3>
                    <p>Store public keys only. Private key material is rejected.</p>
                  </div>
                </div>
                <section className="table-panel embedded operations-table global-team-key-table" aria-label="Team SSH public keys">
                  <TableHeader columns={["Label", "Fingerprint", "Status", "Actions"]} />
                  {selectedMember.sshKeys.length ? (
                    selectedMember.sshKeys.map((key) => (
                      <div className="table-row" key={`${selectedMember.id}-${key.id}`}>
                        <span>{key.label}</span>
                        <code>{key.fingerprint}</code>
                        <StatusPill value={key.status} />
                        <span className="row-actions">
                          <button className="secondary-action compact" onClick={() => editSshKey(selectedMember, key.id)} type="button">
                            Edit
                          </button>
                          <button className="secondary-action compact" disabled={key.status === "retired"} onClick={() => retireSshKey(selectedMember, key.id)} type="button">
                            Retire
                          </button>
                        </span>
                      </div>
                    ))
                  ) : (
                    <OperationsEmptyState message="No SSH public keys are configured for this member." />
                  )}
                </section>
                <div className="form-grid team-modal-grid">
                  <label>
                    <span>Key label</span>
                    <input
                      aria-label="SSH key label"
                      onChange={(event) => setKeyForm((current) => ({ ...current, label: event.target.value }))}
                      value={keyForm.label}
                    />
                  </label>
                  <label className="wide-field">
                    <span>OpenSSH public key</span>
                    <textarea
                      aria-label="OpenSSH public key"
                      onChange={(event) => setKeyForm((current) => ({ ...current, publicKey: event.target.value }))}
                      rows={4}
                      value={keyForm.publicKey}
                    />
                  </label>
                </div>
                <div className="form-actions">
                  <button className="primary-action" disabled={!keyForm.publicKey.trim() || status === "saving"} onClick={saveSshKey} type="button">
                    {keyForm.keyId ? "Update SSH Key" : "Add SSH Key"}
                  </button>
                  <button className="secondary-action" onClick={() => setKeyForm({ keyId: "", memberId: selectedMember.id, label: "piv", publicKey: "" })} type="button">
                    Clear Key Form
                  </button>
                </div>
              </div>
            ) : null}
          </section>
        </div>
      ) : null}

      {panelMode === "import" ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel team-import-floating-panel" aria-label="Import users">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Import</p>
                <h3>Import Users File</h3>
                <p>Select a legacy users file, review the planned changes, then apply them to Global Team.</p>
                <p>Blank UIDs are assigned when new members are created. For existing members, blank UIDs preserve their assignments; missing assignments need reviewed reconciliation.</p>
              </div>
              <button className="secondary-action compact" onClick={closePanel} type="button">
                Close
              </button>
            </div>
            <div className="wizard-steps" aria-label="Users import steps">
              {[
                ["select", "1. Select File"],
                ["preview", "2. Preview Changes"],
                ["apply", "3. Apply Changes"]
              ].map(([step, label]) => (
                <span className={importStep === step ? "active" : ""} key={step}>{label}</span>
              ))}
            </div>
            {importStep === "select" ? (
              <div className="team-import-step">
                <div className="import-file-picker">
                  <div>
                    <h4>Select users.json or users.yml</h4>
                    <p>Use the current file from `spec/ssh/` or another generated user file. Barragan will preview changes before anything is saved.</p>
                  </div>
                  <label className="file-picker-control">
                    <span>Users file</span>
                    <input
                      accept=".json,.yml,.yaml,application/json,text/yaml,text/plain"
                      aria-label="Users import file"
                      onChange={(event) => handleImportFile(event.target.files?.[0] ?? null)}
                      type="file"
                    />
                  </label>
                </div>
                {importForm.content ? (
                  <div className="selected-import-file" aria-label="Selected users import file">
                    <div>
                      <span>Selected file</span>
                      <strong>{importForm.fileName || "users import"}</strong>
                      <small>{importForm.format === "json" ? "users.json" : "users.yml"} · ready to preview</small>
                    </div>
                    <button className="primary-action" disabled={status === "saving"} onClick={previewImport} type="button">
                      Preview Changes
                    </button>
                  </div>
                ) : null}
              </div>
            ) : null}
            {importForm.preview ? (
              <div className="team-import-preview">
                <div className="selected-import-file" aria-label="Selected users import file">
                  <div>
                    <span>Selected file</span>
                    <strong>{importForm.preview.fileName}</strong>
                    <small>{importForm.preview.format === "json" ? "users.json" : "users.yml"}</small>
                  </div>
                  <button className="secondary-action compact" disabled={status === "saving"} onClick={resetImportFile} type="button">
                    Choose Different File
                  </button>
                </div>
                <div className="detail-grid test-deploy-grid">
                  <div>
                    <span>Create</span>
                    <strong>{importForm.preview.summary.creates}</strong>
                  </div>
                  <div>
                    <span>Update</span>
                    <strong>{importForm.preview.summary.updates}</strong>
                  </div>
                  <div>
                    <span>Unchanged</span>
                    <strong>{importForm.preview.summary.unchanged}</strong>
                  </div>
                  <div>
                    <span>Invalid</span>
                    <strong>{importForm.preview.summary.invalid}</strong>
                  </div>
                  <div>
                    <span>SSH keys added</span>
                    <strong>{importForm.preview.summary.keyAdditions}</strong>
                  </div>
                </div>
                {importForm.preview.warnings.length ? (
                  <div className="inline-warning" role="status">
                    {importForm.preview.warnings.join(" ")}
                  </div>
                ) : null}
                {importForm.appliedMessage ? (
                  <div className="inline-info" role="status">
                    {importForm.appliedMessage}
                  </div>
                ) : null}
                <section className="table-panel embedded operations-table team-import-preview-table" aria-label="Users import preview">
                  <TableHeader columns={["User ID", "Action", "UID", "Groups", "SSH Keys", "Changes / Errors"]} />
                  {importForm.preview.records.map((record) => (
                    <div className="table-row" key={`import-preview-${record.sourceIndex}-${record.username || "invalid"}`}>
                      <span>
                        <strong>{record.username || `record ${record.sourceIndex}`}</strong>
                        <small>{record.displayName}</small>
                        {record.status ? <small>Account: {record.status}</small> : null}
                      </span>
                      <StatusPill value={record.action} />
                      <span>{record.desiredUid ?? (() => {
                        const existing = members.find((member) => member.id === record.memberId || member.username === record.username);
                        return existing ? existing.desiredUid ?? "Needs reconciliation"
                          : record.action === "create" && !importForm.appliedMessage ? "Assigned on apply" : "Not assigned";
                      })()}</span>
                      <span>{record.defaultInfraGroups.join(", ") || "none"}</span>
                      <span>{record.keyAdditions} new / {record.existingKeyCount} existing</span>
                      <span>{record.errors.length ? record.errors.join("; ") : record.changes.join(", ") || "no changes"}</span>
                    </div>
                  ))}
                </section>
                <div className="form-actions">
                  {importStep !== "apply" ? (
                    <button className="primary-action" disabled={status === "saving"} onClick={applyImport} type="button">
                      Apply Changes
                    </button>
                  ) : null}
                  <button className="secondary-action" onClick={closePanel} type="button">
                    {importStep === "apply" ? "Done" : "Cancel"}
                  </button>
                </div>
              </div>
            ) : null}
          </section>
        </div>
      ) : null}
    </section>
  );
}

type EngagementTeamPanelMode = "include" | "configure" | null;

type EngagementTeamConfigureFormState = {
  membershipId: string;
  inheritInfraGroups: boolean;
  infraGroups: string[];
  status: string;
};

const emptyEngagementTeamConfigureForm: EngagementTeamConfigureFormState = {
  membershipId: "",
  inheritInfraGroups: true,
  infraGroups: ["redteam", "volunteer"],
  status: "active"
};

function infrastructureStateLabel(value: string): string {
  const labels: Record<string, string> = {
    pending_enable: "Pending Enable",
    enabled: "Enabled",
    pending_disable: "Pending Disable",
    disabled: "Disabled",
    unknown: "Unknown"
  };
  return labels[value] ?? "Unknown";
}

function EngagementTeamPanel({ engagementId }: { engagementId: string | null }) {
  const [workspace, setWorkspace] = useState<EngagementTeamWorkspace | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "saving" | "ready" | "error">("idle");
  const [message, setMessage] = useState("");
  const [panelMode, setPanelMode] = useState<EngagementTeamPanelMode>(null);
  const [includeMemberIds, setIncludeMemberIds] = useState<string[]>([]);
  const [configureForm, setConfigureForm] = useState<EngagementTeamConfigureFormState>(emptyEngagementTeamConfigureForm);
  const [plan, setPlan] = useState<EngagementAccessPlan | null>(null);
  const [job, setJob] = useState<JobRunDetail | null>(null);
  const [accessConsoleOpen, setAccessConsoleOpen] = useState(false);

  const loadTeam = () => {
    if (!engagementId) {
      setWorkspace(null);
      setStatus("idle");
      return Promise.resolve(null);
    }
    setStatus("loading");
    setMessage("");
    return apiClient
      .engagementTeam(engagementId)
      .then((response) => {
        setWorkspace(response);
        setStatus("ready");
        return response;
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not load engagement team."));
        return null;
      });
  };

  useEffect(() => {
    setPanelMode(null);
    setIncludeMemberIds([]);
    setConfigureForm(emptyEngagementTeamConfigureForm);
    setPlan(null);
    setJob(null);
    setAccessConsoleOpen(false);
    void loadTeam();
  }, [engagementId]);

  useEffect(() => {
    const jobId = job?.id;
    if (!jobId || !["queued", "running"].includes(job.status)) {
      return;
    }

    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(jobId)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          setJob(response.job);
          setStatus(finished ? (response.job.status === "succeeded" ? "ready" : "error") : "saving");
          setMessage(finished ? `Core-host access job ${response.job.status} in ${response.job.id}.` : teamAccessJobProgressMessage(response.job));
          if (finished) {
            void loadTeam();
          }
        })
        .catch(() => {
          if (!cancelled) {
            setStatus("error");
            setMessage("Could not refresh core-host access job.");
          }
        });
    };

    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [job?.id, job?.status]);

  const closePanel = () => {
    setPanelMode(null);
    setIncludeMemberIds([]);
    setConfigureForm(emptyEngagementTeamConfigureForm);
  };

  const openIncludePanel = () => {
    setIncludeMemberIds([]);
    setConfigureForm(emptyEngagementTeamConfigureForm);
    setPanelMode("include");
  };

  const openConfigurePanel = (membership: EngagementTeamMembership) => {
    setConfigureForm({
      membershipId: membership.id,
      inheritInfraGroups: membership.infraGroupsOverride === null,
      infraGroups: membership.infraGroupsOverride ?? membership.effectiveInfraGroups,
      status: membership.status
    });
    setPanelMode("configure");
  };

  const includeOperators = async () => {
    if (!engagementId || includeMemberIds.length === 0) {
      return;
    }
    setStatus("saving");
    setMessage("");
    setPlan(null);
    setJob(null);
    try {
      let latest: EngagementTeamWorkspace | null = null;
      for (const memberId of includeMemberIds) {
        const response = await apiClient.enrollEngagementTeamMember(engagementId, {
          memberId,
          inheritInfraGroups: true,
          infraAccessEnabled: true,
          status: "active"
        });
        latest = response;
      }
      if (latest) {
        setWorkspace(latest);
      }
      setStatus("ready");
      setMessage(`${includeMemberIds.length} operator${includeMemberIds.length === 1 ? "" : "s"} included in this engagement.`);
      closePanel();
    } catch (error: unknown) {
      setStatus("error");
      setMessage(barraganApiErrorSummary(error, "Could not include operators in this engagement."));
    }
  };

  const saveConfiguredMembership = () => {
    if (!engagementId || !configureForm.membershipId) {
      return;
    }
    setStatus("saving");
    setMessage("");
    setPlan(null);
    setJob(null);
    const nextStatus = configureForm.status;
    const body = {
      infraAccessEnabled: nextStatus === "active",
      status: nextStatus,
      ...(configureForm.inheritInfraGroups ? { inheritInfraGroups: true } : { infraGroupsOverride: configureForm.infraGroups })
    };
    apiClient
      .updateEngagementTeamMembership(engagementId, configureForm.membershipId, body)
      .then((response) => {
        setWorkspace(response);
        setStatus("ready");
        setMessage(`${response.membership.member.username} updated for this engagement.`);
        closePanel();
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not update engagement team membership."));
      });
  };

  const removeMembership = (membership: EngagementTeamMembership) => {
    if (!engagementId) {
      return;
    }
    setStatus("saving");
    setMessage("");
    setPlan(null);
    setJob(null);
    apiClient
      .removeEngagementTeamMembership(engagementId, membership.id)
      .then((response) => {
        setWorkspace(response);
        setStatus("ready");
        setMessage(`${response.membership.member.username} marked Pending Disable for this engagement.`);
        closePanel();
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not remove engagement team membership."));
      });
  };

  const applyAccessChanges = () => {
    if (!engagementId) {
      return;
    }
    setStatus("saving");
    setMessage("Starting core-host access apply.");
    setJob(null);
    setAccessConsoleOpen(true);
    apiClient
      .engagementAccessApply(engagementId, { requestedBy: "operator" })
      .then((response) => {
        const stillRunning = ["queued", "running"].includes(response.job.status);
        setPlan(response.plan);
        setJob(response.job);
        setStatus(stillRunning ? "saving" : response.job.status === "succeeded" ? "ready" : "error");
        setMessage(stillRunning ? teamAccessJobProgressMessage(response.job) : `Core-host access job ${response.job.status} in ${response.job.id}.`);
        if (!stillRunning) {
          void loadTeam();
        }
      })
      .catch((error: unknown) => {
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not apply core-host access changes."));
      });
  };

  const activeMemberIds = new Set((workspace?.memberships ?? []).filter((membership) => membership.status !== "removed").map((membership) => membership.memberId));
  const includeCandidates = (workspace?.availableMembers ?? []).filter((member) => member.status === "active" && !activeMemberIds.has(member.id));
  const includeCandidateIds = includeCandidates.map((member) => member.id);
  const allIncludeCandidatesSelected = includeCandidateIds.length > 0 && includeCandidateIds.every((memberId) => includeMemberIds.includes(memberId));
  const toggleAllIncludeCandidates = () => {
    setIncludeMemberIds(allIncludeCandidatesSelected ? [] : includeCandidateIds);
  };
  const supportedInfraGroups = workspace?.supportedInfraGroups ?? ["redteam", "core", "volunteer", "infra"];
  const memberships = workspace?.memberships ?? [];
  const selectedMembership = memberships.find((membership) => membership.id === configureForm.membershipId) ?? null;
  const pendingAccessChanges = memberships.some((membership) => ["pending_enable", "pending_disable", "unknown"].includes(membership.infrastructureState));

  return (
    <section className="workflow-view" aria-label="Engagement team">
      <div className="workflow-panel">
        <div>
          <p className="eyebrow">Engagement</p>
          <h3>Team</h3>
          <p>Include operators and manage their core-host Linux group membership for this engagement.</p>
        </div>
        <div className="section-actions">
          <span className={`status ${status === "error" ? "error" : "ready"}`}>{status}</span>
          <button className="primary-action compact" disabled={!engagementId || status === "saving"} onClick={openIncludePanel} type="button">
            Include Operator
          </button>
          <button className="secondary-action compact" disabled={!engagementId || status === "saving"} onClick={() => void loadTeam()} type="button">
            Refresh
          </button>
        </div>
      </div>
      {message ? (
        <div className={status === "error" ? "inline-alert" : "inline-warning"} role="status">
          {message}
        </div>
      ) : null}

      <section className="table-panel embedded operations-table engagement-team-table" aria-label="Engagement team memberships">
        <TableHeader columns={["User ID", "Linux Groups", "Status", "Infrastructure State", "Actions"]} />
        {memberships.length ? (
          memberships.map((membership) => (
            <div className="table-row engagement-row" key={membership.id}>
              <span>
                <strong>{membership.member.username}</strong>
                <small>{membership.member.displayName || membership.member.email || membership.status}</small>
              </span>
              <span>
                <strong>{membership.effectiveInfraGroups.join(", ") || "none"}</strong>
                <small>{membership.infraGroupsOverride === null ? "inherited" : "engagement override"}</small>
              </span>
              <StatusPill value={membership.status} />
              <StatusPill value={infrastructureStateLabel(membership.infrastructureState)} />
              <span className="row-actions">
                <button className="secondary-action compact" onClick={() => openConfigurePanel(membership)} type="button">
                  Configure
                </button>
              </span>
            </div>
          ))
        ) : (
          <OperationsEmptyState message="No operators are enrolled in this engagement yet." />
        )}
      </section>

      <section className="guided-review" aria-label="Engagement access propagation">
        <div className="section-heading">
          <div>
            <h3>Core Host Access</h3>
            <p>Apply the homebase/proxy account state. Named operators are not propagated to sketch nodes.</p>
          </div>
          <div className="section-actions">
            <button className="primary-action compact" disabled={!engagementId || status === "saving" || !pendingAccessChanges} onClick={applyAccessChanges} type="button">
              Apply Access Changes
            </button>
            {job || status === "saving" ? (
              <button className="secondary-action compact" onClick={() => setAccessConsoleOpen(true)} type="button">
                View Console
              </button>
            ) : null}
          </div>
        </div>
        {plan ? (
          <div className="detail-grid test-deploy-grid">
            <div>
              <span>Mode</span>
              <strong>{plan.mode}</strong>
            </div>
            <div>
              <span>Core users</span>
              <strong>{plan.coreUsers.length}</strong>
            </div>
            <div>
              <span>Target hosts</span>
              <strong>{plan.targetHosts.join(", ")}</strong>
            </div>
            <div>
              <span>Sketch targets</span>
              <strong>{plan.sketchTargets.length}</strong>
            </div>
          </div>
        ) : null}
        {plan?.warnings.length ? (
          <div className="inline-alert" role="status">
            {plan.warnings.join("; ")}
          </div>
        ) : null}
      </section>

      {panelMode === "include" ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel team-floating-panel" aria-label="Include operator">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Include</p>
                <h3>Include Operator</h3>
                <p>Select active Global Team operators to include in this engagement. They will inherit their default Linux groups.</p>
              </div>
              <button className="secondary-action compact" onClick={closePanel} type="button">
                Close
              </button>
            </div>
            <div className="bulk-selection-bar">
              <label className="checkbox-inline">
                <input
                  aria-label="Select all visible operators"
                  checked={allIncludeCandidatesSelected}
                  disabled={!includeCandidates.length || status === "saving"}
                  onChange={toggleAllIncludeCandidates}
                  type="checkbox"
                />
                <span>Select all visible operators</span>
              </label>
              <small>{includeMemberIds.length} selected</small>
            </div>
            <section className="table-panel embedded operations-table available-operators-table" aria-label="Available operators">
              <TableHeader columns={["Select", "User ID", "Default Groups", "SSH Keys"]} />
              {includeCandidates.length ? (
                includeCandidates.map((member) => (
                  <div className="table-row" key={`include-${member.id}`}>
                    <label className="checkbox-inline">
                      <input
                        checked={includeMemberIds.includes(member.id)}
                        onChange={() => setIncludeMemberIds((current) => toggleListValue(current, member.id))}
                        type="checkbox"
                      />
                      <span>Select</span>
                    </label>
                    <span>
                      <strong>{member.username}</strong>
                      <small>{member.displayName || member.email || "No profile details"}</small>
                    </span>
                    <span>{member.defaultInfraGroups.join(", ") || "none"}</span>
                    <span>{member.sshKeys.filter((key) => key.status === "active").length} active</span>
                  </div>
                ))
              ) : (
                <OperationsEmptyState message="No active global operators are available to include." />
              )}
            </section>
            <div className="form-actions">
              <button className="primary-action" disabled={!includeMemberIds.length || status === "saving"} onClick={() => void includeOperators()} type="button">
                Include Selected
              </button>
              <button className="secondary-action" onClick={closePanel} type="button">
                Cancel
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {accessConsoleOpen && (job || message || status === "saving") ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel job-console-panel" aria-label="Core access job console">
            <div className="section-heading">
              <div>
                <h3>Core access console</h3>
                <ProgressConsolePrimaryLine
                  job={job}
                  summary={job ? teamAccessJobProgressMessage(job) : message || "Starting core-host access apply."}
                />
              </div>
              <button className="secondary-action compact" onClick={() => setAccessConsoleOpen(false)} type="button">
                Close
              </button>
            </div>
            <pre>{jobConsoleText(job, message || "Starting core-host access apply.", teamAccessConsoleEventText)}</pre>
          </section>
        </div>
      ) : null}

      {panelMode === "configure" && selectedMembership ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel team-floating-panel" aria-label="Configure engagement operator">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Configure</p>
                <h3>{`Configure ${selectedMembership.member.username}`}</h3>
                <p>Adjust this operator's engagement Linux groups and access state for core hosts.</p>
              </div>
              <button className="secondary-action compact" onClick={closePanel} type="button">
                Close
              </button>
            </div>
            <div className="detail-grid test-deploy-grid">
              <div>
                <span>User ID</span>
                <strong>{selectedMembership.member.username}</strong>
              </div>
              <div>
                <span>Global status</span>
                <strong>{selectedMembership.member.status}</strong>
              </div>
              <div>
                <span>Infrastructure state</span>
                <strong>{infrastructureStateLabel(selectedMembership.infrastructureState)}</strong>
              </div>
              <div>
                <span>Active SSH keys</span>
                <strong>{selectedMembership.member.sshKeys.filter((key) => key.status === "active").length}</strong>
              </div>
            </div>
            <div className="form-grid team-modal-grid">
              <label>
                <span>Engagement status</span>
                <select
                  aria-label="Engagement operator status"
                  onChange={(event) => setConfigureForm((current) => ({ ...current, status: event.target.value }))}
                  value={configureForm.status}
                >
                  <option value="active">active</option>
                  <option value="suspended">suspended</option>
                  <option value="removed">removed</option>
                </select>
              </label>
              <label className="checkbox-inline wide-field">
                <input
                  checked={configureForm.inheritInfraGroups}
                  onChange={(event) => setConfigureForm((current) => ({ ...current, inheritInfraGroups: event.target.checked }))}
                  type="checkbox"
                />
                <span>Inherit global infrastructure groups</span>
              </label>
              {!configureForm.inheritInfraGroups ? (
                <div className="wide-field checkbox-group" role="group" aria-label="Engagement infrastructure groups">
                  <span>Engagement infrastructure groups</span>
                  {supportedInfraGroups.map((group) => (
                    <label key={`engagement-team-group-${group}`}>
                      <input
                        checked={configureForm.infraGroups.includes(group)}
                        onChange={() =>
                          setConfigureForm((current) => ({
                            ...current,
                            infraGroups: toggleListValue(current.infraGroups, group)
                          }))
                        }
                        type="checkbox"
                      />
                      <span>{group}</span>
                    </label>
                  ))}
                </div>
              ) : null}
            </div>
            <section className="table-panel embedded operations-table global-team-key-table" aria-label="Engagement operator SSH public keys">
              <TableHeader columns={["Label", "Fingerprint", "Status"]} />
              {selectedMembership.member.sshKeys.length ? (
                selectedMembership.member.sshKeys.map((key) => (
                  <div className="table-row" key={`engagement-${selectedMembership.id}-${key.id}`}>
                    <span>{key.label}</span>
                    <code>{key.fingerprint}</code>
                    <StatusPill value={key.status} />
                  </div>
                ))
              ) : (
                <OperationsEmptyState message="No SSH public keys are configured for this operator." />
              )}
            </section>
            <div className="form-actions">
              <button className="primary-action" disabled={status === "saving"} onClick={saveConfiguredMembership} type="button">
                Save Operator
              </button>
              <button className="secondary-action" onClick={closePanel} type="button">
                Cancel
              </button>
              <button className="danger-action" disabled={selectedMembership.status === "removed" || status === "saving"} onClick={() => removeMembership(selectedMembership)} type="button">
                Remove Operator
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </section>
  );
}

function EngagementManagementPage({
  engagements,
  onArchive,
  onCreate,
  onDelete,
  onEdit,
  onOpenWorkspace,
  onReconcile
}: {
  engagements: EngagementSummary[];
  onArchive: (engagementId: string) => Promise<EngagementDetail>;
  onCreate: (metadata: EngagementMetadataFormState, sketchStateSchema: "split-v1" | "provider-keyed-v2") => Promise<EngagementDetail>;
  onDelete: (engagementId: string) => Promise<EngagementDetail>;
  onEdit: (engagementId: string, metadata: EngagementMetadataFormState) => Promise<EngagementDetail>;
  onOpenWorkspace: (engagementId: string) => void;
  onReconcile: (engagementId: string) => Promise<EngagementSummary>;
}) {
  const [filter, setFilter] = useState<"current" | "active" | "attention" | "destroyed" | "archived" | "retired" | "all">("current");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<EngagementMetadataFormState>(emptyEngagementMetadata);
  const [creationSketchStateSchema, setCreationSketchStateSchema] = useState<"split-v1" | "provider-keyed-v2">("split-v1");
  const [managementStatus, setManagementStatus] = useState<"idle" | "saving" | "ready" | "error">("idle");
  const [managementMessage, setManagementMessage] = useState("");

  const visibleEngagements = engagements.filter((engagement) => {
    if (filter === "all") {
      return true;
    }
    if (filter === "current") {
      return isActiveEngagement(engagement) || isOperationallyCurrentEngagement(engagement);
    }
    if (filter === "active") {
      return engagement.lifecycle?.state === "active";
    }
    if (filter === "attention") {
      return engagement.lifecycle?.attentionRequired === true;
    }
    if (filter === "destroyed") {
      return engagement.lifecycle?.state === "destroyed";
    }
    return engagement.status === filter;
  });
  const editingEngagement = engagements.find((engagement) => engagement.id === editingId) ?? null;
  const formReady = form.name.trim().length > 0 && form.owner.trim().length > 0 && managementStatus !== "saving";

  const resetForm = () => {
    setEditingId(null);
    setForm(emptyEngagementMetadata);
    setCreationSketchStateSchema("split-v1");
    setManagementStatus("idle");
    setManagementMessage("");
  };

  const loadForEdit = (engagement: EngagementSummary) => {
    setEditingId(engagement.id);
    setForm(metadataFromEngagement(engagement));
    setManagementStatus("idle");
    setManagementMessage("");
  };

  const save = () => {
    if (!formReady) {
      return;
    }
    setManagementStatus("saving");
    const request = editingId ? onEdit(editingId, form) : onCreate(form, creationSketchStateSchema);
    request
      .then(() => {
        resetForm();
        setManagementStatus("ready");
        setManagementMessage("");
      })
      .catch(() => {
        setManagementStatus("error");
        setManagementMessage("Unable to save engagement metadata.");
      });
  };

  const runAction = (action: () => Promise<EngagementDetail>) => {
    setManagementStatus("saving");
    setManagementMessage("");
    action()
      .then(() => {
        setManagementStatus("ready");
        setManagementMessage("");
      })
      .catch((error: unknown) => {
        setManagementStatus("error");
        setManagementMessage(
          error instanceof Error
            ? error.message
            : "Unable to update engagement. Check whether infrastructure is still active."
        );
      });
  };

  const reconcile = (engagementId: string) => {
    setManagementStatus("saving");
    setManagementMessage("");
    onReconcile(engagementId)
      .then((engagement) => {
        setManagementStatus("ready");
        setManagementMessage(`Lifecycle reconciled: ${engagement.lifecycle?.label ?? "Unknown"}.`);
      })
      .catch((error: unknown) => {
        setManagementStatus("error");
        setManagementMessage(error instanceof Error ? error.message : "Unable to reconcile lifecycle.");
      });
  };

  return (
    <section className="workflow-view" aria-label="Engagement management">
      <div className="workflow-panel">
        <div>
          <p className="eyebrow">Global</p>
          <h3>Engagements</h3>
          <p>Create and maintain engagement workspace metadata. Infrastructure is configured inside each selected workspace.</p>
        </div>
        <span className={`status ${managementStatus === "error" ? "error" : "ready"}`}>{managementStatus}</span>
      </div>
      {managementMessage ? (
        <div className="inline-alert" role="alert">
          {managementMessage}
        </div>
      ) : null}

      <section className="guided-form engagement-metadata-form" aria-label="Engagement metadata form">
        <label>
          <span>Name</span>
          <input
            aria-label="Engagement metadata name"
            onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
            value={form.name}
          />
        </label>
        <label>
          <span>Owner</span>
          <input
            aria-label="Engagement metadata owner"
            onChange={(event) => setForm((current) => ({ ...current, owner: event.target.value }))}
            value={form.owner}
          />
        </label>
        <label>
          <span>Documentation link</span>
          <input
            aria-label="Engagement documentation link"
            onChange={(event) => setForm((current) => ({ ...current, documentationUrl: event.target.value }))}
            value={form.documentationUrl}
          />
        </label>
        <label>
          <span>Jira link</span>
          <input
            aria-label="Engagement Jira link"
            onChange={(event) => setForm((current) => ({ ...current, jiraUrl: event.target.value }))}
            value={form.jiraUrl}
          />
        </label>
        <label className="wide-field">
          <span>Description</span>
          <textarea
            aria-label="Engagement description"
            onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))}
            rows={3}
            value={form.description}
          />
        </label>
        {!editingEngagement && import.meta.env.DEV ? (
          <label>
            <span>Sketch state (DevTest pilot)</span>
            <select
              aria-label="Sketch state (DevTest pilot)"
              onChange={(event) => setCreationSketchStateSchema(event.target.value as "split-v1" | "provider-keyed-v2")}
              value={creationSketchStateSchema}
            >
              <option value="split-v1">Standard</option>
              <option value="provider-keyed-v2">Provider-keyed pilot</option>
            </select>
          </label>
        ) : null}
        <div className="form-actions">
          <button className="primary-action" disabled={!formReady} onClick={save} type="button">
            {editingEngagement ? "Save Engagement" : "Create Engagement"}
          </button>
          <button className="secondary-action" onClick={resetForm} type="button">
            Clear
          </button>
        </div>
      </section>

      <div className="filter-tabs" aria-label="Engagement status filter">
        {(["current", "active", "attention", "destroyed", "archived", "retired", "all"] as const).map((filterOption) => (
          <button
            className={filter === filterOption ? "filter-tab active" : "filter-tab"}
            key={filterOption}
            onClick={() => setFilter(filterOption)}
            type="button"
          >
            {filterOption[0].toUpperCase() + filterOption.slice(1)}
          </button>
        ))}
      </div>

      <section className="table-panel embedded engagement-management-table" aria-label="Engagement metadata list">
        <TableHeader columns={["Engagement", "Infrastructure", "Owner", "Links", "Actions"]} />
        {visibleEngagements.length > 0 ? (
          visibleEngagements.map((engagement) => {
            const lifecycleGuidance = engagementLifecycleActionGuidance(engagement);
            return (
            <div className="table-row engagement-row" key={engagement.id}>
              <span>
                <strong>{engagement.name}</strong>
                <small>{engagement.description || "No description"}</small>
              </span>
              <span className="engagement-lifecycle-cell">
                <strong className={`lifecycle-state lifecycle-${engagement.lifecycle?.state ?? "unknown"}`}>
                  {engagement.lifecycle?.label ?? "Unknown"}
                </strong>
                <small>Record: {engagement.status.replaceAll("_", " ")}</small>
              </span>
              <span>{engagement.owner}</span>
              <span>
                {engagement.documentationUrl ? "docs" : "no docs"} · {engagement.jiraUrl ? "jira" : "no jira"}
              </span>
              <span className="row-actions">
                <button
                  className="secondary-action compact"
                  disabled={!isActiveEngagement(engagement)}
                  onClick={() => onOpenWorkspace(engagement.id)}
                  type="button"
                >
                  Open Workspace
                </button>
                <button className="secondary-action compact" onClick={() => loadForEdit(engagement)} type="button">
                  Edit
                </button>
                <button
                  className="secondary-action compact"
                  disabled={managementStatus === "saving"}
                  onClick={() => reconcile(engagement.id)}
                  type="button"
                >
                  Reconcile
                </button>
                <button
                  className="secondary-action compact"
                  disabled={engagement.status === "archived" || engagement.status === "retired" || engagement.lifecycle?.terminal === false}
                  onClick={() => runAction(() => onArchive(engagement.id))}
                  title={lifecycleGuidance}
                  type="button"
                >
                  Archive
                </button>
                <button
                  className="secondary-action compact"
                  disabled={engagement.status === "retired" || engagement.lifecycle?.terminal === false}
                  onClick={() => runAction(() => onDelete(engagement.id))}
                  title={lifecycleGuidance}
                  type="button"
                >
                  Retire
                </button>
                {lifecycleGuidance ? <small className="lifecycle-action-guidance">{lifecycleGuidance}</small> : null}
              </span>
            </div>
            );
          })
        ) : (
          <div className="empty-state inline">
            <h3>No engagements</h3>
            <p>Create an engagement workspace or adjust the status filter.</p>
          </div>
        )}
      </section>
    </section>
  );
}

const domainBucketSections: Array<{ key: keyof DomainGroups; title: string; empty: string }> = [
  {
    key: "currently_being_used",
    title: "Currently Being Used",
    empty: "No domains are actively assigned to current engagements."
  },
  {
    key: "waiting_to_be_used",
    title: "Waiting To Be Used",
    empty: "No clear, unassigned domains are waiting for engagement use."
  },
  {
    key: "used_in_past_engagements",
    title: "Used In Past Engagements",
    empty: "No released, historical, or blocked domains are recorded yet."
  }
];

const domainRiskStatusOptions: Array<{ value: DomainRiskStatus; label: string }> = [
  { value: "clear", label: "Clear" },
  { value: "burned", label: "Burned" },
  { value: "quarantined", label: "Quarantine" },
  { value: "cooldown", label: "Cooldown" }
];

const domainCatalogStateOptions = [
  { value: "auto", label: "Auto" },
  { value: "currently_being_used", label: "Currently Being Used" },
  { value: "waiting_to_be_used", label: "Waiting To Be Used" },
  { value: "used_in_past_engagements", label: "Used In Past Engagements" }
];

function DomainInventoryPage({ engagements }: { engagements: EngagementSummary[] }) {
  const [domainGroups, setDomainGroups] = useState<DomainGroups>(emptyDomainGroups());
  const [domainStatus, setDomainStatus] = useState<"idle" | "loading" | "ready" | "saving" | "error">("idle");
  const [syncStatus, setSyncStatus] = useState<"idle" | "running" | "ready" | "error">("idle");
  const [domainMessage, setDomainMessage] = useState("");
  const [assignmentForm, setAssignmentForm] = useState<DomainAssignmentFormState | null>(null);
  const [selectedDomainId, setSelectedDomainId] = useState<string | null>(null);
  const assignableEngagements = engagements.filter(isActiveEngagement);
  const allDomains = useMemo(
    () => [...domainGroups.currently_being_used, ...domainGroups.waiting_to_be_used, ...domainGroups.used_in_past_engagements],
    [domainGroups]
  );
  const selectedDomain = selectedDomainId ? allDomains.find((domain) => domain.id === selectedDomainId) ?? null : null;

  const loadDomains = () => {
    setDomainStatus("loading");
    setDomainMessage("");
    return apiClient
      .domains()
      .then((response) => {
        setDomainGroups(normalizeDomainGroups(response.domains));
        setDomainStatus("ready");
        return response.domains;
      })
      .catch((error: unknown) => {
        setDomainStatus("error");
        setDomainMessage(barraganApiErrorSummary(error, "Could not load domain inventory."));
        return emptyDomainGroups();
      });
  };

  useEffect(() => {
    void loadDomains();
  }, []);

  const openAssignment = (domain: DomainSummary) => {
    const defaultEngagementId = domain.engagement
      ? assignableEngagements.find((engagement) => engagement.id !== domain.engagement?.id)?.id ?? ""
      : "";
    setSelectedDomainId(domain.id);
    setAssignmentForm({
      domainId: domain.id,
      engagementId: defaultEngagementId,
      purpose: purposeInputValue(domain.purposeTags, domain.purpose || "rti"),
      notes: "",
      confirmationToken: "",
      confirmationRequired: null,
      releaseWarningVisible: false
    });
    setDomainMessage("");
  };

  const openDomainDetails = (domain: DomainSummary) => {
    setSelectedDomainId(domain.id);
    setAssignmentForm(null);
    setDomainMessage("");
  };

  const closeDomainDetails = () => {
    setSelectedDomainId(null);
    setAssignmentForm(null);
  };

  const assignDomain = () => {
    if (!assignmentForm?.domainId || !assignmentForm.engagementId) {
      return;
    }
    const body: {
      engagementId: string;
      purposeTags: string[];
      notes: string;
      assignedBy: string;
      confirmationToken?: string;
    } = {
      engagementId: assignmentForm.engagementId,
      purposeTags: normalizedPurposeTagsFromInput(assignmentForm.purpose),
      notes: assignmentForm.notes,
      assignedBy: "operator"
    };
    if (assignmentForm.confirmationRequired) {
      body.confirmationToken = assignmentForm.confirmationToken;
    }
    setDomainStatus("saving");
    setDomainMessage("");
    apiClient
      .assignDomain(assignmentForm.domainId, body)
      .then((response) => {
        setDomainGroups((current) => replaceDomainInGroups(current, response.domain));
        setAssignmentForm(null);
        setSelectedDomainId(null);
        setDomainStatus("ready");
        setDomainMessage(`${response.domain.domainName} assigned to ${response.assignment.engagementName}.`);
      })
      .catch((error: unknown) => {
        const confirmationRequired = domainConfirmationFromError(error);
        if (confirmationRequired) {
          setAssignmentForm((current) =>
            current
              ? {
                  ...current,
                  confirmationRequired,
                  confirmationToken: ""
                }
              : current
          );
          setDomainStatus("ready");
          setDomainMessage(`Assignment requires confirmation: ${confirmationRequired.reasons.join("; ")}`);
          return;
        }
        setDomainStatus("error");
        setDomainMessage(barraganApiErrorSummary(error, "Could not assign domain."));
      });
  };

  const releaseDomain = (domain: DomainSummary) => {
    setDomainStatus("saving");
    setDomainMessage("");
    apiClient
      .releaseDomain(domain.id, { releasedBy: "operator" })
      .then((response) => {
        setDomainGroups((current) => replaceDomainInGroups(current, response.domain));
        setAssignmentForm(null);
        setSelectedDomainId(null);
        setDomainStatus("ready");
        setDomainMessage(`${response.domain.domainName} released without deleting assignment history.`);
      })
      .catch((error: unknown) => {
        setDomainStatus("error");
        setDomainMessage(barraganApiErrorSummary(error, "Could not release domain."));
      });
  };

  const requestReleaseDomain = (domain: DomainSummary) => {
    if (domainDnsRecordCount(domain) > 0) {
      setAssignmentForm((current) =>
        current && current.domainId === domain.id
          ? {
              ...current,
              releaseWarningVisible: true
            }
          : current
      );
      return;
    }
    releaseDomain(domain);
  };

  const saveDomainProperties = (
    domain: DomainSummary,
    draft: {
      catalogState: string;
      notes: string;
      purpose: string;
      riskStatus: DomainRiskStatus;
    }
  ) => {
    const nextPurposeTags = normalizedPurposeTagsFromInput(draft.purpose);
    const currentPurposeTags = normalizedPurposeTagsFromInput(purposeInputValue(domain.purposeTags, domain.purpose));
    const purposeChanged = Boolean(domain.engagement) && nextPurposeTags.join("|") !== currentPurposeTags.join("|");
    const catalogChanged = draft.catalogState !== domain.catalogState;
    const notesChanged = draft.notes.trim() !== (domain.notes || "").trim();
    const riskChanged = draft.riskStatus !== domain.healthRisk.status;
    if (!purposeChanged && !catalogChanged && !notesChanged && !riskChanged) {
      return;
    }
    setDomainStatus("saving");
    setDomainMessage("");
    let latestDomain: DomainSummary = domain;
    const riskOrNotesStep =
      notesChanged || riskChanged
        ? apiClient
            .updateDomainRisk(domain.id, {
              riskStatus: draft.riskStatus,
              riskFlags: draft.riskStatus === "clear" ? [] : domain.healthRisk.flags.length ? domain.healthRisk.flags : [draft.riskStatus],
              cooldownUntil: draft.riskStatus === "cooldown" ? domain.healthRisk.cooldownUntil : "",
              assignableOverride: domain.healthRisk.assignableOverride,
              notes: draft.notes
            })
            .then((response) => response.domain)
        : Promise.resolve(domain);

    riskOrNotesStep
      .then((updatedDomain) => {
        latestDomain = updatedDomain;
        if (!catalogChanged) {
          return updatedDomain;
        }
        return apiClient.updateDomainCatalogState(domain.id, { catalogState: draft.catalogState }).then((response) => response.domain);
      })
      .then((updatedDomain) => {
        latestDomain = updatedDomain;
        if (!purposeChanged) {
          return null;
        }
        return apiClient.updateDomainAssignment(domain.id, { purposeTags: nextPurposeTags });
      })
      .then((assignmentResponse) => {
        if (assignmentResponse) {
          latestDomain = assignmentResponse.domain;
        }
        setDomainGroups((current) => replaceDomainInGroups(current, latestDomain));
        setDomainStatus("ready");
        setDomainMessage(`${latestDomain.domainName} updated.`);
      })
      .catch((error: unknown) => {
        setDomainStatus("error");
        setDomainMessage(barraganApiErrorSummary(error, "Could not update domain."));
      });
  };

  const syncNamecheap = () => {
    setSyncStatus("running");
    setDomainMessage("");
    apiClient
      .syncNamecheapDomains({ includeHosts: true, requestedBy: "operator" })
      .then((response) => {
        setSyncStatus("ready");
        setDomainMessage(
          `Namecheap sync completed: ${response.domainsSynced} domains and ${response.hostSnapshots} DNS snapshots. Job ${response.job.id}.`
        );
        return loadDomains();
      })
      .catch((error: unknown) => {
        const body = error instanceof BarraganApiError ? recordValue(error.body) : {};
        const job = recordValue(body.job);
        const jobId = typeof job.id === "string" ? ` Job ${job.id}.` : "";
        setSyncStatus("error");
        setDomainStatus("error");
        setDomainMessage(`Namecheap sync failed.${jobId} Sensitive credential details were not returned.`);
      });
  };

  return (
    <section className="workflow-view" aria-label="Domain inventory">
      <div className="workflow-panel">
        <div>
          <p className="eyebrow">Global</p>
          <h3>Domains</h3>
          <p>Track registrar inventory, engagement assignment, history, and operator risk state.</p>
        </div>
        <div className="section-actions">
          <span className={`status ${domainStatus === "error" || syncStatus === "error" ? "error" : "ready"}`}>
            {syncStatus === "running" ? "syncing" : domainStatus}
          </span>
          <button className="secondary-action compact" disabled={domainStatus === "loading" || domainStatus === "saving"} onClick={() => void loadDomains()} type="button">
            Refresh
          </button>
          <button className="primary-action compact" disabled={syncStatus === "running"} onClick={syncNamecheap} type="button">
            {syncStatus === "running" ? "Syncing Namecheap" : "Sync Namecheap"}
          </button>
        </div>
      </div>

      {domainMessage ? (
        <div className={domainStatus === "error" || syncStatus === "error" ? "inline-alert" : "inline-warning"} role="status">
          {domainMessage}
        </div>
      ) : null}

      {domainBucketSections.map((section) => (
        <DomainBucketTable
          domains={domainGroups[section.key]}
          emptyMessage={section.empty}
          key={section.key}
          onOpenDomainDetails={openDomainDetails}
          title={section.title}
        />
      ))}

      {selectedDomain ? (
        <DomainDetailPanel
          assignableEngagements={assignableEngagements}
          assignmentForm={assignmentForm}
          domain={selectedDomain}
          onAssignDomain={assignDomain}
          onCancelAssignment={() => setAssignmentForm(null)}
          onClose={closeDomainDetails}
          onOpenAssignment={openAssignment}
          onReleaseDomain={releaseDomain}
          onRequestReleaseDomain={requestReleaseDomain}
          onSetAssignmentForm={setAssignmentForm}
          onSaveDomainProperties={saveDomainProperties}
          saving={domainStatus === "saving"}
        />
      ) : null}
    </section>
  );
}

function DomainBucketTable({
  domains,
  emptyMessage,
  onOpenDomainDetails,
  title
}: {
  domains: DomainSummary[];
  emptyMessage: string;
  onOpenDomainDetails: (domain: DomainSummary) => void;
  title: string;
}) {
  return (
    <section className="table-panel embedded operations-table domain-inventory-table" aria-label={title}>
      <div className="section-heading table-section-heading">
        <h3>{title}</h3>
        <span>{domains.length} domains</span>
      </div>
      <TableHeader columns={["Domain", "Registrar", "Registration", "Expiration", "Health/Risk", "Engagement", "Purpose", "Notes"]} />
      {domains.length ? (
        domains.map((domain) => (
          <div className="domain-entry" key={`${title}-${domain.id}`}>
            <div
              aria-label={`Open ${domain.domainName} details`}
              className={`table-row domain-row ${domainRiskClassName(domain.healthRisk.status)}`}
              data-testid={`domain-row-${domain.domainName}`}
              onClick={() => onOpenDomainDetails(domain)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onOpenDomainDetails(domain);
                }
              }}
              role="button"
              tabIndex={0}
            >
              <span>
                <strong>{domain.domainName}</strong>
              </span>
              <span>
                <strong>{domain.registrar || "N/A"}</strong>
                <small>{domain.providerStatus || "provider status unknown"}</small>
              </span>
              <span>
                <strong>{formatDomainDate(domain.registration.createdAt)}</strong>
                <small>Created</small>
              </span>
              <span>
                <strong>{formatDomainDate(domain.registration.expiresAt)}</strong>
                <small>Auto-renew {domain.registration.autoRenew ? "on" : "off"}</small>
              </span>
              <span className="domain-risk-cell">
                <DomainRiskBadge status={domain.healthRisk.status} />
                <small>{domain.healthRisk.flags.length ? domain.healthRisk.flags.join(", ") : "no flags"}</small>
              </span>
              <span>
                <strong>{domain.engagement?.name ?? "Unassigned"}</strong>
                {domain.engagement ? null : <small>{domain.bucket.replace(/_/g, " ")}</small>}
              </span>
              <DomainPurposeTags purpose={domain.purpose} purposeTags={domain.purposeTags} />
              <span className="domain-notes-cell" title={domain.notes || "No notes"}>{domain.notes || "No notes"}</span>
            </div>
          </div>
        ))
      ) : (
        <OperationsEmptyState message={emptyMessage} />
      )}
    </section>
  );
}

function DomainDetailPanel({
  assignableEngagements,
  assignmentForm,
  domain,
  onAssignDomain,
  onCancelAssignment,
  onClose,
  onOpenAssignment,
  onReleaseDomain,
  onRequestReleaseDomain,
  onSaveDomainProperties,
  onSetAssignmentForm,
  saving
}: {
  assignableEngagements: EngagementSummary[];
  assignmentForm: DomainAssignmentFormState | null;
  domain: DomainSummary;
  onAssignDomain: () => void;
  onCancelAssignment: () => void;
  onClose: () => void;
  onOpenAssignment: (domain: DomainSummary) => void;
  onReleaseDomain: (domain: DomainSummary) => void;
  onRequestReleaseDomain: (domain: DomainSummary) => void;
  onSaveDomainProperties: (domain: DomainSummary, draft: { catalogState: string; notes: string; purpose: string; riskStatus: DomainRiskStatus }) => void;
  onSetAssignmentForm: (value: DomainAssignmentFormState | ((current: DomainAssignmentFormState | null) => DomainAssignmentFormState | null)) => void;
  saving: boolean;
}) {
  const initialPurposeDraft = purposeInputValue(domain.purposeTags, domain.purpose);
  const [purposeDraft, setPurposeDraft] = useState(initialPurposeDraft);
  const [catalogStateDraft, setCatalogStateDraft] = useState(domain.catalogState || "auto");
  const [notesDraft, setNotesDraft] = useState(domain.notes || "");
  const [riskDraft, setRiskDraft] = useState<DomainRiskStatus>(domain.healthRisk.status);
  useEffect(() => {
    setPurposeDraft(purposeInputValue(domain.purposeTags, domain.purpose));
  }, [domain.id, domain.purpose, domain.purposeTags]);
  useEffect(() => {
    setCatalogStateDraft(domain.catalogState || "auto");
  }, [domain.id, domain.catalogState]);
  useEffect(() => {
    setNotesDraft(domain.notes || "");
  }, [domain.id, domain.notes]);
  useEffect(() => {
    setRiskDraft(domain.healthRisk.status);
  }, [domain.id, domain.healthRisk.status]);
  const purposeChanged =
    Boolean(domain.engagement) && normalizedPurposeTagsFromInput(purposeDraft).join("|") !== normalizedPurposeTagsFromInput(initialPurposeDraft).join("|");
  const catalogChanged = catalogStateDraft !== (domain.catalogState || "auto");
  const notesChanged = notesDraft.trim() !== (domain.notes || "").trim();
  const riskChanged = riskDraft !== domain.healthRisk.status;
  const hasDomainChanges = purposeChanged || catalogChanged || notesChanged || riskChanged;
  const resetDrafts = () => {
    setPurposeDraft(purposeInputValue(domain.purposeTags, domain.purpose));
    setCatalogStateDraft(domain.catalogState || "auto");
    setNotesDraft(domain.notes || "");
    setRiskDraft(domain.healthRisk.status);
  };

  if (assignmentForm?.domainId === domain.id) {
    return (
      <div className="modal-scrim" role="presentation">
        <section className="floating-panel domain-floating-panel" aria-label={`Domain assignment dialog for ${domain.domainName}`}>
          <DomainAssignmentPanel
            assignableEngagements={assignableEngagements}
            domain={domain}
            form={assignmentForm}
            onAssignDomain={onAssignDomain}
            onCancel={onCancelAssignment}
            onReleaseDomain={() => onReleaseDomain(domain)}
            onRequestReleaseDomain={() => onRequestReleaseDomain(domain)}
            onSetForm={onSetAssignmentForm}
            saving={saving}
          />
        </section>
      </div>
    );
  }

  return (
    <div className="modal-scrim" role="presentation">
      <section className="floating-panel domain-floating-panel" aria-label={`Domain details for ${domain.domainName}`}>
        <div className="section-heading">
          <div>
            <p className="eyebrow">Domain</p>
            <h3>{domain.domainName}</h3>
            <p>{domain.engagement ? `Assigned to ${domain.engagement.name}.` : "Not assigned to an active engagement."}</p>
          </div>
        </div>

        <div className="domain-detail-grid">
          <span className="domain-detail-card">
            <small>Registrar</small>
            <strong>{domain.registrar || "N/A"}</strong>
            <em>{domain.providerStatus || "provider status unknown"}</em>
          </span>
          <span className="domain-detail-card">
            <small>Registration</small>
            <strong>{formatDomainDate(domain.registration.createdAt)}</strong>
            <em>Created</em>
          </span>
          <span className="domain-detail-card">
            <small>Expiration</small>
            <strong>{formatDomainDate(domain.registration.expiresAt)}</strong>
            <em>Auto-renew {domain.registration.autoRenew ? "on" : "off"}</em>
          </span>
          <button
            className="domain-detail-card domain-engagement-card"
            aria-label={domain.engagement ? `Manage engagement assignment for ${domain.domainName}` : `Assign engagement for ${domain.domainName}`}
            disabled={saving || (!domain.engagement && assignableEngagements.length === 0)}
            onClick={() => onOpenAssignment(domain)}
            type="button"
          >
            <small>Engagement</small>
            <strong>{domain.engagement?.name ?? "Unassigned"}</strong>
            <em>{domain.engagement ? "Click to change or release" : "Click to assign"}</em>
          </button>
          <span className="domain-detail-card">
            <small>Catalog State</small>
            <div className="domain-detail-catalog-editor">
              <select
                aria-label={`Catalog state for ${domain.domainName}`}
                onChange={(event) => setCatalogStateDraft(event.target.value)}
                value={catalogStateDraft}
              >
                {domainCatalogStateOptions.map((option) => (
                  <option key={`${domain.id}-${option.value}`} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <em>{catalogStateDraft === "auto" ? "Derived from assignment history" : "Operator catalog override"}</em>
          </span>
          <span className="domain-detail-card">
            <small>Risk</small>
            <div className="domain-detail-risk-editor">
              <select
                aria-label={`Risk status for ${domain.domainName}`}
                disabled={saving}
                onChange={(event) => setRiskDraft(event.target.value as DomainRiskStatus)}
                value={riskDraft}
              >
                {domainRiskStatusOptions.map((option) => (
                  <option key={`${domain.id}-${option.value}`} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
            <em>{riskStatusLabel(riskDraft)}</em>
          </span>
          <span className="domain-detail-card">
            <small>Purpose</small>
            {domain.engagement ? (
              <div className="domain-detail-purpose-editor">
                <input
                  aria-label={`Edit purpose for ${domain.domainName}`}
                  onChange={(event) => setPurposeDraft(event.target.value)}
                  placeholder="rti, redirector"
                  value={purposeDraft}
                />
              </div>
            ) : (
              <>
                <DomainPurposeTags purpose={domain.purpose} purposeTags={domain.purposeTags} />
                <em>Assign domain to set purpose</em>
              </>
            )}
          </span>
          <span className="domain-detail-card">
            <small>Last Sync</small>
            <strong>{formatDomainDateTime(domain.lastSyncedAt)}</strong>
            <em>Provider inventory</em>
          </span>
        </div>

        <section className="domain-detail-notes" aria-label={`Notes for ${domain.domainName}`}>
          <div className="section-heading compact-heading">
            <h4>Notes</h4>
          </div>
          <textarea
            aria-label={`Edit notes for ${domain.domainName}`}
            onChange={(event) => setNotesDraft(event.target.value)}
            rows={5}
            value={notesDraft}
          />
        </section>

        <div className="domain-detail-footer-actions">
          <button
            className="secondary-action compact"
            disabled={saving || !hasDomainChanges}
            onClick={resetDrafts}
            type="button"
          >
            Clear Changes
          </button>
          <button
            className="primary-action compact"
            disabled={saving || !hasDomainChanges}
            onClick={() => onSaveDomainProperties(domain, { catalogState: catalogStateDraft, notes: notesDraft, purpose: purposeDraft, riskStatus: riskDraft })}
            type="button"
          >
            Save Changes
          </button>
          <button className="secondary-action compact" onClick={onClose} type="button">
            Close
          </button>
        </div>
      </section>
    </div>
  );
}

function DomainAssignmentPanel({
  assignableEngagements,
  domain,
  form,
  onAssignDomain,
  onCancel,
  onReleaseDomain,
  onRequestReleaseDomain,
  onSetForm,
  saving
}: {
  assignableEngagements: EngagementSummary[];
  domain: DomainSummary;
  form: DomainAssignmentFormState;
  onAssignDomain: () => void;
  onCancel: () => void;
  onReleaseDomain: () => void;
  onRequestReleaseDomain: () => void;
  onSetForm: (value: DomainAssignmentFormState | ((current: DomainAssignmentFormState | null) => DomainAssignmentFormState | null)) => void;
  saving: boolean;
}) {
  const confirmationMatches = !form.confirmationRequired || form.confirmationToken === form.confirmationRequired.token;
  const ready = Boolean(form.engagementId) && confirmationMatches && !saving;
  const dnsRecordCount = domainDnsRecordCount(domain);

  if (form.releaseWarningVisible) {
    return (
      <section className="domain-assignment-panel" aria-label={`Release ${domain.domainName}`}>
        <div className="section-heading">
          <div>
            <h4>Release {domain.domainName}</h4>
            <p>{domain.engagement ? `Currently assigned to ${domain.engagement.name}.` : "No active engagement assignment."}</p>
          </div>
          <DomainRiskBadge status={domain.healthRisk.status} />
        </div>
        <div className="inline-warning domain-release-warning" role="alert">
          <strong>There are active DNS records set for this domain, you should remove them before releasing the domain.</strong>
          <span>{dnsRecordCount} DNS {dnsRecordCount === 1 ? "record" : "records"} are present in the latest provider snapshot.</span>
          {domain.dnsSummary?.recordsPreview?.length ? (
            <ul>
              {domain.dnsSummary.recordsPreview.map((record, index) => (
                <li key={`${domain.id}-release-record-${index}`}>
                  {record.type || "Record"} {record.name || "@"} {"->"} {record.address || "N/A"}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        <div className="workflow-actions">
          <button
            className="secondary-action compact"
            disabled={saving}
            onClick={() =>
              onSetForm((current) =>
                current
                  ? {
                      ...current,
                      releaseWarningVisible: false
                    }
                  : current
              )
            }
            type="button"
          >
            Cancel
          </button>
          <button className="danger-action compact" disabled={saving} onClick={onReleaseDomain} type="button">
            Release Anyway
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="domain-assignment-panel" aria-label={`Assign ${domain.domainName}`}>
      <div className="section-heading">
        <div>
          <h4>{domain.engagement ? "Manage Assignment" : "Assign"} {domain.domainName}</h4>
          <p>{domain.engagement ? `Currently assigned to ${domain.engagement.name}.` : "No active engagement assignment."}</p>
        </div>
        <DomainRiskBadge status={domain.healthRisk.status} />
      </div>
      <div className="domain-assignment-grid">
        <label>
          <span>Engagement</span>
          <select
            aria-label="Domain assignment engagement"
            onChange={(event) => onSetForm((current) => (current ? { ...current, engagementId: event.target.value } : current))}
            value={form.engagementId}
          >
            <option value="">Select engagement</option>
            {assignableEngagements.map((engagement) => (
              <option key={engagement.id} value={engagement.id}>
                {engagement.name}
              </option>
            ))}
          </select>
        </label>
        <div className="purpose-field">
          <label>
            <span>Purpose</span>
            <input
              aria-label="Domain assignment purpose"
              onChange={(event) => onSetForm((current) => (current ? { ...current, purpose: event.target.value } : current))}
              placeholder="website, redirector, email, dns"
              value={form.purpose}
            />
          </label>
        </div>
        <label className="wide-field">
          <span>Assignment Notes</span>
          <textarea
            aria-label="Domain assignment notes"
            onChange={(event) => onSetForm((current) => (current ? { ...current, notes: event.target.value } : current))}
            placeholder="Why this domain is being assigned or reused"
            rows={2}
            value={form.notes}
          />
        </label>
        {form.confirmationRequired ? (
          <div className="domain-confirmation" role="group" aria-label={`Confirmation required for ${domain.domainName}`}>
            <div>
              <strong>Type {form.confirmationRequired.token}</strong>
              <span>{form.confirmationRequired.reasons.join("; ")}</span>
            </div>
            <label>
              <span>Confirmation token</span>
              <input
                aria-label={`Confirmation token for ${domain.domainName}`}
                onChange={(event) => onSetForm((current) => (current ? { ...current, confirmationToken: event.target.value } : current))}
                value={form.confirmationToken}
              />
            </label>
          </div>
        ) : null}
      </div>
      <div className="workflow-actions">
        <button className="primary-action" disabled={!ready} onClick={onAssignDomain} type="button">
          {form.confirmationRequired ? "Confirm Assignment" : domain.engagement ? "Change Assignment" : "Assign Domain"}
        </button>
        {domain.engagement ? (
          <button className="secondary-action compact danger-action" disabled={saving} onClick={onRequestReleaseDomain} type="button">
            Release Domain
          </button>
        ) : null}
        <button className="secondary-action compact" onClick={onCancel} type="button">
          Cancel
        </button>
      </div>
    </section>
  );
}

function DomainRiskBadge({ status }: { status: DomainRiskStatus }) {
  return <span className={`domain-risk-badge ${domainRiskClassName(status)}`}>{riskStatusLabel(status)}</span>;
}

function DomainPurposeTags({ purpose, purposeTags }: { purpose: string; purposeTags?: string[] }) {
  const tags = purposeInputValue(purposeTags, purpose).split(",").map((tag) => tag.trim()).filter(Boolean);
  if (!tags.length) {
    return <span>N/A</span>;
  }
  return (
    <span className="purpose-chip-list">
      {tags.map((tag) => (
        <span className="purpose-chip" key={`${purpose}-${tag}`}>
          {tag}
        </span>
      ))}
    </span>
  );
}

function EngagementDomainsPanel({ engagementId }: { engagementId: string | null }) {
  const [domains, setDomains] = useState<DomainSummary[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");

  useEffect(() => {
    if (!engagementId) {
      setDomains([]);
      setStatus("idle");
      return;
    }
    let cancelled = false;
    setStatus("loading");
    apiClient
      .engagementDomains(engagementId)
      .then((response) => {
        if (!cancelled) {
          setDomains(response.domains ?? []);
          setStatus("ready");
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDomains([]);
          setStatus("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [engagementId]);

  return (
    <section className="table-panel embedded operations-table engagement-domains-table" aria-label="Assigned domains">
      <div className="section-heading table-section-heading">
        <div>
          <h3>Assigned Domains</h3>
          <p>Inventory assignments only; DNS records remain read-only provider snapshots.</p>
        </div>
        <span>{status}</span>
      </div>
      <TableHeader columns={["Domain", "Registrar", "Risk", "Purpose", "Notes", "Last Sync"]} />
      {domains.length ? (
        domains.map((domain) => (
          <div className={`table-row domain-row ${domainRiskClassName(domain.healthRisk.status)}`} key={`eng-domain-${domain.id}`}>
            <span>{domain.domainName}</span>
            <span>{domain.registrar || "N/A"}</span>
            <span className="domain-risk-cell">
              <DomainRiskBadge status={domain.healthRisk.status} />
            </span>
            <DomainPurposeTags purpose={domain.purpose} purposeTags={domain.purposeTags} />
            <span>{domain.notes || "No notes"}</span>
            <span>{formatDomainDateTime(domain.lastSyncedAt)}</span>
          </div>
        ))
      ) : (
        <OperationsEmptyState message="No domains are assigned to this engagement." />
      )}
    </section>
  );
}

const fallbackDnsRecordTypes = ["A", "AAAA", "CNAME", "TXT", "MX", "NS"];

function CertificateManagerPage({ engagementId }: { engagementId: string | null }) {
  const [workspace, setWorkspace] = useState<CertificateManagerWorkspace | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "saving" | "error">("loading");
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState("");
  const [draft, setDraft] = useState({ name: "", source: "letsencrypt" as CertificateAsset["source"], proxy: "", identifiers: "", notes: "", pem: "" });
  const [panel, setPanel] = useState<"new" | "defaults" | "details" | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [notesDraft, setNotesDraft] = useState("");
  const [job, setJob] = useState<JobRunDetail | null>(null);
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [lifecycleConfirmation, setLifecycleConfirmation] = useState<{
    certificateId: string;
    action: "renew" | "reissue" | "revoke";
    value: string;
  } | null>(null);

  const load = () => {
    if (!engagementId) return;
    setStatus("loading");
    void apiClient.certificateManager(engagementId).then(({ certificateManager }) => {
      setWorkspace(certificateManager);
      setEmail(certificateManager.profile.acmeEmail || "");
      setDraft((current) => ({ ...current, proxy: current.proxy || certificateManager.proxies[0]?.id || "" }));
      setStatus("ready");
    }).catch((error) => {
      setStatus("error");
      setMessage(barraganApiErrorSummary(error, "Could not load Certificate Manager."));
    });
  };

  useEffect(load, [engagementId]);

  const saveProfile = () => {
    if (!engagementId) return;
    setStatus("saving");
    void apiClient.updateCertificateProfile(engagementId, { acmeEmail: email, defaultEnvironment: "production" }).then(() => {
      setMessage("Let's Encrypt defaults saved.");
      setPanel(null);
      load();
    }).catch((error) => {
      setStatus("error");
      setMessage(barraganApiErrorSummary(error, "Could not save the ACME profile."));
    });
  };

  const createCertificate = () => {
    if (!engagementId) return;
    const identifiers = draft.identifiers.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
    setStatus("saving");
    void apiClient.createCertificate(engagementId, {
      name: draft.name,
      source: draft.source,
      targetProxyId: draft.proxy,
      identifiers,
      notes: draft.notes,
      ...(draft.source === "external" ? { certificatePem: draft.pem } : {})
    }).then((response) => {
      setDraft((current) => ({ ...current, name: "", identifiers: "", notes: "", pem: "" }));
      setPanel(null);
      if (response.certificate.source === "external") {
        setMessage("External certificate metadata imported.");
        return load();
      }
      setMessage("Certificate asset created. Starting issuance.");
      return apiClient.certificateLifecycle(engagementId, response.certificate.id, "issue", { acmeEnvironment: "production" }).then((lifecycle) => {
        setJob(lifecycle.job);
        setConsoleOpen(true);
        setMessage(certificateManagerJobProgressMessage(lifecycle.job));
        load();
      });
    }).catch((error) => {
      setStatus("error");
      setMessage(barraganApiErrorSummary(error, "Could not create certificate asset."));
    });
  };

  const runLifecycle = (
    certificate: CertificateAsset,
    action: "issue" | "renew" | "reissue" | "revoke",
    productionConfirmation = ""
  ) => {
    if (!engagementId) return;
    setStatus("saving");
    void apiClient.certificateLifecycle(engagementId, certificate.id, action, {
      acmeEnvironment: "production",
      ...(productionConfirmation ? { productionConfirmation } : {})
    }).then((response) => {
      setJob(response.job);
      setConsoleOpen(true);
      setLifecycleConfirmation(null);
      setMessage(certificateManagerJobProgressMessage(response.job));
      load();
    }).catch((error) => {
      setStatus("error");
      setMessage(barraganApiErrorSummary(error, `Could not ${action} certificate.`));
    });
  };

  useEffect(() => {
    if (!job || !["queued", "running"].includes(job.status)) {
      return;
    }
    let cancelled = false;
    let timer: number | null = null;
    const refresh = () => {
      void apiClient.job(job.id).then((response) => {
        if (cancelled) return;
        setJob(response.job);
        setMessage(certificateManagerJobProgressMessage(response.job));
        setStatus(response.job.status === "failed" ? "error" : "ready");
        if (!["queued", "running"].includes(response.job.status)) {
          load();
          return;
        }
        timer = window.setTimeout(refresh, 1200);
      }).catch(() => {
        if (!cancelled) {
          setStatus("error");
          setMessage("Could not refresh certificate job.");
        }
      });
    };
    timer = window.setTimeout(refresh, 1200);
    return () => {
      cancelled = true;
      if (timer !== null) {
        window.clearTimeout(timer);
      }
    };
  }, [job?.id, job?.status]);

  const certificates = workspace?.certificates ?? [];
  const selectedCertificate = certificates.find((certificate) => certificate.id === selectedId) ?? null;
  const selectedSummary = selectedCertificate ? certificateManagerSummary(selectedCertificate) : null;

  const openDetails = (certificate: CertificateAsset) => {
    setSelectedId(certificate.id);
    setNotesDraft(certificate.notes || "");
    setLifecycleConfirmation(null);
    setPanel("details");
  };

  const beginLifecycle = (certificate: CertificateAsset, action: "renew" | "reissue" | "revoke") => {
    if (certificate.source !== "letsencrypt") {
      runLifecycle(certificate, action);
      return;
    }
    setLifecycleConfirmation({ certificateId: certificate.id, action, value: "" });
    setMessage("");
  };

  const saveNotes = () => {
    if (!engagementId || !selectedCertificate) return;
    setStatus("saving");
    void apiClient.updateCertificate(engagementId, selectedCertificate.id, { notes: notesDraft }).then((response) => {
      setWorkspace((current) => current ? { ...current, certificates: current.certificates.map((certificate) => certificate.id === response.certificate.id ? response.certificate : certificate) } : current);
      setMessage("Certificate notes saved.");
      setStatus("ready");
    }).catch((error) => {
      setStatus("error");
      setMessage(barraganApiErrorSummary(error, "Could not save certificate notes."));
    });
  };

  return (
    <section className="workflow-stack" aria-label="Certificate Manager">
      <div className="section-heading">
        <div><h3>Certificate Manager</h3><p>Issue and track engagement certificate assets, then bind them explicitly from HTTPS inbound channels.</p></div>
        <div className="section-actions">
          {job ? <button className="secondary-action compact" onClick={() => setConsoleOpen(true)} type="button">Log</button> : null}
          <button className="secondary-action compact" onClick={() => setPanel("defaults")} type="button">Configure Defaults</button>
          <button className="primary-action compact" onClick={() => setPanel("new")} type="button">New Certificate</button>
          <button className="secondary-action compact" onClick={load} type="button">Refresh</button>
        </div>
      </div>
      <p className="guardrail-hint">DNS-01 is orchestrated by Barragan. Namecheap credentials remain in Barragan, private keys remain on the selected proxy, and each certificate is scoped to exactly one proxy.</p>

      <section className="table-panel embedded operations-table" aria-label="Certificate inventory">
        <div className="section-heading"><div><h4>Certificate inventory</h4><p>{certificates.length} engagement certificate assets.</p></div></div>
        {!certificates.length ? <OperationsEmptyState message="No certificate assets are tracked yet." /> : (
          <>
            <div className="table-header certificate-inventory-row" role="row">
              <span>CN / SANs</span>
              <span>Source</span>
              <span>Not Before</span>
              <span>Expiration</span>
              <span>Edge</span>
              <span>Proxy</span>
              <span>Status</span>
              <span>Bindings</span>
              <span>Notes</span>
            </div>
            {certificates.map((certificate) => {
              const summary = certificateManagerSummary(certificate);
              return (
                <button className="table-row certificate-inventory-row certificate-table-row" key={certificate.id} onClick={() => openDetails(certificate)} role="row" type="button">
                  <span>{summary.names}</span>
                  <span>{certificateSourceLabel(certificate.source)}</span>
                  <span>{formatOperationsTimestamp(summary.notBefore)}</span>
                  <span>{formatOperationsTimestamp(summary.expiresAt)}</span>
                  <span>{summary.edges || "—"}</span>
                  <span>{certificate.targetProxyId || "—"}</span>
                  <span><span className={`status ${certificate.status === "active" ? "ready" : certificate.status.includes("ing") ? "running" : "idle"}`}>{certificate.status}</span></span>
                  <span>{certificate.bindings.length}</span>
                  <span>{certificate.notes || "—"}</span>
                </button>
              );
            })}
          </>
        )}
      </section>
      {message ? <p role={status === "error" ? "alert" : "status"}>{message}</p> : null}
      {panel === "new" ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel certificate-floating-panel" aria-label="New Certificate">
            <div className="section-heading"><div><h3>New Certificate</h3><p>Create and issue a certificate for this engagement.</p></div><button className="secondary-action compact" onClick={() => setPanel(null)} type="button">Close</button></div>
            <div className="form-grid compact-form">
              <label><span>Name</span><input aria-label="Certificate name" onChange={(event) => setDraft({ ...draft, name: event.target.value })} value={draft.name} /></label>
              <label><span>Source</span><select aria-label="Certificate source" onChange={(event) => setDraft({ ...draft, source: event.target.value as CertificateAsset["source"] })} value={draft.source}><option value="letsencrypt">Let's Encrypt</option><option value="self-signed">Self-Signed</option><option value="external">External</option></select></label>
              <label><span>Target proxy</span><select aria-label="Certificate target proxy" onChange={(event) => setDraft({ ...draft, proxy: event.target.value })} value={draft.proxy}><option value="">Select proxy</option>{workspace?.proxies.map((proxy) => <option key={proxy.id} value={proxy.id}>{proxy.label}</option>)}</select></label>
              <label className="wide-field"><span>DNS names / SANs</span><textarea aria-label="Certificate DNS identifiers" onChange={(event) => setDraft({ ...draft, identifiers: event.target.value })} placeholder={"shazbot.party\n*.shazbot.party"} value={draft.identifiers} /></label>
              <label className="wide-field"><span>Notes</span><textarea aria-label="Certificate notes" onChange={(event) => setDraft({ ...draft, notes: event.target.value })} placeholder="Purpose, owning app, operator context, or setup notes." value={draft.notes} /></label>
              {draft.source === "external" ? <label className="wide-field"><span>Public certificate / chain PEM</span><textarea aria-label="External public certificate PEM" onChange={(event) => setDraft({ ...draft, pem: event.target.value })} value={draft.pem} /></label> : null}
            </div>
            <p className="guardrail-hint">SANs are immutable after creation. Wildcards use DNS-01. Private keys stay on the selected proxy. Notes are Barragan metadata only.</p>
            <div className="section-actions"><button className="primary-action compact" disabled={status === "saving" || !draft.name || !draft.proxy || !draft.identifiers.trim()} onClick={createCertificate} type="button">{draft.source === "external" ? "Import Certificate" : "Create and Issue Certificate"}</button></div>
          </section>
        </div>
      ) : null}
      {panel === "defaults" ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel certificate-floating-panel" aria-label="Let's Encrypt Defaults">
            <div className="section-heading"><div><h3>Let's Encrypt Defaults</h3><p>Defaults for production issuance and automated renewal.</p></div><button className="secondary-action compact" onClick={() => setPanel(null)} type="button">Close</button></div>
            <div className="form-grid compact-form">
              <label><span>Account email</span><input aria-label="ACME account email" onChange={(event) => setEmail(event.target.value)} placeholder="operator@example.com" value={email} /></label>
            </div>
            <p className="guardrail-hint">Barragan requests production certificates by default. DNS-01 records are orchestrated from Barragan without copying registrar credentials to operators.</p>
            <div className="section-actions"><button className="primary-action compact" disabled={status === "saving"} onClick={saveProfile} type="button">Save Defaults</button></div>
          </section>
        </div>
      ) : null}
      {panel === "details" && selectedCertificate && selectedSummary ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel certificate-floating-panel" aria-label={`Certificate details for ${selectedCertificate.name}`}>
            <div className="section-heading"><div><h3>{selectedCertificate.name}</h3><p>{selectedSummary.names}</p></div><button className="secondary-action compact" onClick={() => { setLifecycleConfirmation(null); setPanel(null); }} type="button">Close</button></div>
            <div className="certificate-detail-sections">
              <section className="certificate-detail-section" aria-label="Certificate overview">
                <h4>Overview</h4>
                <div className="certificate-detail-row-list">
                  <CertificateDetailRow label="Source" value={certificateSourceLabel(selectedCertificate.source)} />
                  <CertificateDetailRow label="Status" value={selectedCertificate.status} />
                  <CertificateDetailRow label="Requested" value={formatOperationsTimestamp(selectedCertificate.createdAt)} />
                  <CertificateDetailRow label="Not Before" value={formatOperationsTimestamp(selectedSummary.notBefore)} />
                  <CertificateDetailRow label="Expiration" value={formatOperationsTimestamp(selectedSummary.expiresAt)} />
                  <CertificateDetailRow label="Last renewed" value={formatOperationsTimestamp(selectedSummary.lastRenewedAt)} />
                  <CertificateDetailRow label="Renewal count" value={selectedSummary.renewalCount} />
                </div>
              </section>
              <section className="certificate-detail-section" aria-label="Certificate binding">
                <h4>Binding</h4>
                <div className="certificate-detail-row-list">
                  <CertificateDetailRow label="Proxy" value={selectedCertificate.targetProxyId || "—"} code />
                  <CertificateDetailRow label="Edge / channel" value={selectedSummary.edges || "—"} code />
                  <CertificateDetailRow label="Binding count" value={selectedCertificate.bindings.length} />
                </div>
              </section>
              <section className="certificate-detail-section" aria-label="Certificate identity">
                <h4>Certificate identity</h4>
                <div className="certificate-detail-row-list">
                  <CertificateDetailRow label="Issuer" value={selectedSummary.current?.issuer || "—"} code />
                  <CertificateDetailRow label="Serial" value={selectedSummary.current?.serialNumber || "—"} code />
                  <CertificateDetailRow label="Fingerprint" value={selectedSummary.current?.fingerprintSha256 || "—"} code />
                </div>
              </section>
            </div>
            <section className="certificate-paths" aria-label="Certificate filesystem paths">
              <span>Certificate filesystem paths</span>
              {certificatePathEntries(selectedSummary.current).length ? certificatePathEntries(selectedSummary.current).map(([label, value]) => <code key={label}>{label}: {value}</code>) : <em>No proxy filesystem paths are recorded yet.</em>}
            </section>
            <section className="certificate-version-history" aria-label="Certificate version history">
              <h4>Version history</h4>
              {selectedCertificate.versions.length ? selectedCertificate.versions.map((version) => <div className="event-row" key={version.id}><span>{version.sequence}</span><span>{version.status}</span><span>{formatOperationsTimestamp(version.issuedAt || version.createdAt)}</span><span>{formatOperationsTimestamp(version.expiresAt)}</span><span>{version.lastJobId || "—"}</span></div>) : <OperationsEmptyState message="No versions recorded yet." />}
            </section>
            <label className="wide-field"><span>Notes</span><textarea aria-label="Edit certificate notes" onChange={(event) => setNotesDraft(event.target.value)} value={notesDraft} /></label>
            <div className="section-actions">
              <button className="secondary-action compact" disabled={status === "saving" || notesDraft === (selectedCertificate.notes || "")} onClick={saveNotes} type="button">Save Notes</button>
              {!selectedCertificate.currentVersionId && selectedCertificate.source !== "external" ? <button className="primary-action compact" onClick={() => runLifecycle(selectedCertificate, "issue")} type="button" title="Issue an existing draft certificate.">Issue</button> : null}
              {selectedCertificate.source === "letsencrypt" && selectedCertificate.status === "active" ? <button className="primary-action compact" onClick={() => beginLifecycle(selectedCertificate, "renew")} type="button" title="Refresh expiration; keep existing private key.">Renew certificate</button> : null}
              {selectedCertificate.source !== "external" && selectedCertificate.status === "active" ? <button className="secondary-action compact" onClick={() => beginLifecycle(selectedCertificate, "reissue")} type="button" title="Rotate private key and request replacement certificate.">Reissue with new key</button> : null}
              {selectedCertificate.source === "letsencrypt" && selectedCertificate.status === "active" ? <button className="danger-action compact" onClick={() => beginLifecycle(selectedCertificate, "revoke")} type="button">Revoke</button> : null}
            </div>
            {lifecycleConfirmation?.certificateId === selectedCertificate.id ? (() => {
              const action = lifecycleConfirmation.action;
              const expected = selectedCertificate.productionConfirmations[action];
              const label = action === "reissue" ? "Reissue with new key" : action === "revoke" ? "Revoke certificate" : "Renew certificate";
              const matches = lifecycleConfirmation.value === expected;
              return (
                <div className="teardown-confirmation" role="group" aria-label={`Production certificate ${action} confirmation`}>
                  <strong>{label}</strong>
                  <p className="guardrail-hint">This changes a production Let's Encrypt certificate. Type the exact phrase to continue.</p>
                  <label>
                    <span>Type <code>{expected}</code></span>
                    <input
                      aria-label={`Production certificate ${action} phrase`}
                      autoComplete="off"
                      onChange={(event) => setLifecycleConfirmation((current) => current ? { ...current, value: event.target.value } : current)}
                      value={lifecycleConfirmation.value}
                    />
                  </label>
                  {lifecycleConfirmation.value && !matches ? <p role="alert">Confirmation does not match the required phrase.</p> : null}
                  <div className="section-actions">
                    <button className="secondary-action compact" onClick={() => setLifecycleConfirmation(null)} type="button">Cancel</button>
                    <button
                      className={action === "revoke" ? "danger-action compact" : "primary-action compact"}
                      disabled={status === "saving" || !matches}
                      onClick={() => runLifecycle(selectedCertificate, action, lifecycleConfirmation.value)}
                      type="button"
                    >
                      Confirm {label}
                    </button>
                  </div>
                </div>
              );
            })() : null}
            <p className="guardrail-hint">Renew refreshes expiration and keeps the existing private key. Reissue rotates the proxy-held private key and requests a replacement certificate.</p>
          </section>
        </div>
      ) : null}
      {consoleOpen && (job || message) ? (
        <div className="modal-scrim nested-modal-scrim" role="presentation">
          <section className="floating-panel channel-console-panel" aria-label="Certificate Manager job console">
            <div className="section-heading">
              <div>
                <h3>Certificate progress console</h3>
                <ProgressConsolePrimaryLine job={job} summary={message || "Certificate job progress."} />
              </div>
              <div className="section-actions">
                <button className="secondary-action compact" onClick={() => void navigator.clipboard.writeText(jobConsoleText(job, message || "No certificate job events are available yet.", certificateConsoleEventText))} type="button">Copy log</button>
                <button className="secondary-action compact" onClick={() => setConsoleOpen(false)} type="button">Close</button>
              </div>
            </div>
            <pre>{jobConsoleText(job, message || "No certificate job events are available yet.", certificateConsoleEventText)}</pre>
          </section>
        </div>
      ) : null}
    </section>
  );
}

function CertificateDetailRow({ label, value, code = false }: { label: string; value: number | string; code?: boolean }) {
  const displayValue = value === "" ? "—" : String(value);
  return (
    <div className="certificate-detail-row">
      <span>{label}</span>
      {code ? <code>{displayValue}</code> : <strong>{displayValue}</strong>}
    </div>
  );
}

function certificateSourceLabel(source: CertificateAsset["source"]): string {
  if (source === "letsencrypt") return "Let's Encrypt";
  if (source === "self-signed") return "Self-Signed";
  if (source === "external") return "External";
  return source;
}

function certificateCurrentVersion(certificate: CertificateAsset): CertificateVersion | null {
  return certificate.currentVersion ?? certificate.versions.find((version) => version.id === certificate.currentVersionId) ?? certificate.versions[certificate.versions.length - 1] ?? null;
}

function certificateManagerSummary(certificate: CertificateAsset) {
  const current = certificateCurrentVersion(certificate);
  const renewedVersions = certificate.versions.filter((version) => version.status === "renewed");
  const lastRenewed = renewedVersions[renewedVersions.length - 1] ?? null;
  const identifiers = certificate.identifiers.length ? certificate.identifiers : [certificate.primaryIdentifier].filter(Boolean);
  return {
    current,
    names: identifiers.join(", ") || certificate.name,
    notBefore: stringValue(current?.publicMetadata?.notBefore) || current?.issuedAt || "",
    expiresAt: current?.expiresAt || "",
    lastRenewedAt: lastRenewed?.issuedAt || lastRenewed?.updatedAt || "",
    renewalCount: renewedVersions.length,
    edges: certificate.bindings.map((binding) => binding.channelId || binding.hostname).filter(Boolean).join(", "),
  };
}

function certificatePathEntries(version: CertificateVersion | null): Array<[string, string]> {
  const paths = version?.paths ?? {};
  return ["liveDir", "versionDir", "fullchain", "cert", "chain", "privkey"]
    .map((key) => [key, stringValue(paths[key])] as [string, string])
    .filter(([, value]) => Boolean(value));
}

function certificateManagerJobProgressMessage(job: JobRunDetail): string {
  const latest = job.events?.[job.events.length - 1];
  if (job.status === "queued") return "Certificate job is queued.";
  if (job.status === "running") return latest ? certificateConsoleEventText(latest) : "Certificate job is running.";
  if (job.status === "succeeded") return "Certificate job succeeded.";
  return "Certificate job failed.";
}

function EngagementDnsPage({ engagementId }: { engagementId: string | null }) {
  const [workspace, setWorkspace] = useState<EngagementDnsWorkspace | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [message, setMessage] = useState("");
  const [editor, setEditor] = useState<DnsEditorState | null>(null);
  const [dnsJob, setDnsJob] = useState<JobRunDetail | null>(null);
  const [dnsConsoleOpen, setDnsConsoleOpen] = useState(false);
  const [dnsConsoleCopied, setDnsConsoleCopied] = useState(false);

  const loadWorkspace = () => {
    if (!engagementId) {
      setWorkspace(null);
      setStatus("idle");
      return Promise.resolve(null);
    }
    setStatus("loading");
    setMessage("");
    return apiClient
      .engagementDns(engagementId)
      .then((response) => {
        setWorkspace(response.dns);
        setStatus("ready");
        return response.dns;
      })
      .catch((error) => {
        setWorkspace(null);
        setStatus("error");
        setMessage(barraganApiErrorSummary(error, "Could not load engagement DNS."));
        return null;
      });
  };

  useEffect(() => {
    void loadWorkspace();
  }, [engagementId]);

  useEffect(() => {
    const job = dnsJob;
    if (!job || !["queued", "running"].includes(job.status)) {
      return;
    }
    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(job.id)
        .then((response) => {
          if (cancelled) {
            return;
          }
          const finished = !["queued", "running"].includes(response.job.status);
          setDnsJob(response.job);
          if (finished) {
            setMessage(dnsJobProgressMessage(response.job));
            setStatus(response.job.status === "failed" ? "error" : "ready");
            void loadWorkspace();
          }
        })
        .catch(() => {
          if (!cancelled) {
            setStatus("error");
            setMessage("Could not refresh DNS apply job.");
          }
        });
    };
    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [dnsJob?.id, dnsJob?.status]);

  const supportedTypes = workspace?.supportedRecordTypes?.length ? workspace.supportedRecordTypes : fallbackDnsRecordTypes;

  const openEditor = (domain: EngagementDnsDomain) => {
    const openFromWorkspace = (dns: EngagementDnsWorkspace | null) => {
      const latestDomain = dns?.domains.find((candidate) => candidate.id === domain.id) ?? workspace?.domains.find((candidate) => candidate.id === domain.id) ?? domain;
      const latestSupportedTypes = dns?.supportedRecordTypes?.length ? dns.supportedRecordTypes : supportedTypes;
      setEditor({
        domain: latestDomain,
        records: dnsEditorRecords(latestDomain, dns?.defaultTtl ?? workspace?.defaultTtl ?? 600, latestSupportedTypes),
        step: "manage",
        status: "idle",
        message: "",
        preview: null
      });
    };
    if (engagementId) {
      void loadWorkspace().then(openFromWorkspace);
      return;
    }
    openFromWorkspace(workspace);
  };

  const updateRecord = (localId: string, patch: Partial<DnsEditorRecord>) => {
    setEditor((current) => {
      if (!current) {
        return current;
      }
      return {
        ...current,
        records: current.records.map((record) => {
          if (record.localId !== localId) {
            return record;
          }
          const next = { ...record, ...patch };
          if (patch.type) {
            next.type = patch.type.toUpperCase();
            next.mxPref = next.type === "MX" ? next.mxPref || "10" : "";
          }
          return next;
        }),
        preview: null,
        step: "manage",
        message: "",
        status: "idle"
      };
    });
  };

  const addRecord = () => {
    setEditor((current) =>
      current
        ? {
            ...current,
            records: [
              ...current.records,
              {
                localId: `dns-${Date.now()}-${current.records.length}`,
                name: "@",
                type: "A",
                address: "",
                ttl: String(workspace?.defaultTtl ?? 600),
                mxPref: ""
              }
            ],
            preview: null,
            step: "manage",
            message: "",
            status: "idle"
          }
        : current
    );
  };

  const removeRecord = (localId: string) => {
    setEditor((current) =>
      current
        ? {
            ...current,
            records: current.records.filter((record) => record.localId !== localId),
            preview: null,
            step: "manage",
            message: "",
            status: "idle"
          }
        : current
    );
  };

  const previewDns = () => {
    if (!engagementId || !editor) {
      return;
    }
    const records = dnsPayloadRecords(editor.records, workspace?.defaultTtl ?? 600);
    setEditor({ ...editor, status: "previewing", message: "Previewing DNS changes.", preview: null, step: "manage" });
    apiClient
      .previewEngagementDns(engagementId, { domainId: editor.domain.id, records, requestedBy: "operator" })
      .then((response) => {
        setEditor((current) =>
          current
            ? {
                ...current,
                status: "ready",
                message: "DNS preview is ready.",
                preview: response.preview,
                step: "preview"
              }
            : current
        );
      })
      .catch((error) => {
        setEditor((current) =>
          current
            ? {
                ...current,
                status: "error",
                message: barraganApiErrorSummary(error, "Could not preview DNS records."),
                preview: null,
                step: "manage"
              }
            : current
        );
      });
  };

  const cancelDnsPreview = () => {
    if (!engagementId || !editor) {
      return;
    }
    const domainId = editor.domain.id;
    setEditor({ ...editor, status: "previewing", message: "Reloading current DNS records.", preview: null, step: "manage" });
    void loadWorkspace().then((dns) => {
      const latestDomain = dns?.domains.find((domain) => domain.id === domainId) ?? editor.domain;
      setEditor({
        domain: latestDomain,
        records: dnsEditorRecords(latestDomain, dns?.defaultTtl ?? workspace?.defaultTtl ?? 600, dns?.supportedRecordTypes?.length ? dns.supportedRecordTypes : supportedTypes),
        step: "manage",
        status: "idle",
        message: "",
        preview: null
      });
    });
  };

  const applyDns = () => {
    if (!engagementId || !editor?.preview) {
      return;
    }
    const records = dnsPayloadRecords(editor.records, workspace?.defaultTtl ?? 600);
    setEditor({ ...editor, status: "applying", message: "Starting DNS apply job." });
    apiClient
      .applyEngagementDns(engagementId, {
        domainId: editor.domain.id,
        records,
        currentFingerprint: editor.preview.currentFingerprint,
        requestedBy: "operator"
      })
      .then((response: EngagementDnsApplyResponse) => {
        const running = ["queued", "running"].includes(response.job.status);
        setDnsJob(response.job);
        setDnsConsoleCopied(false);
        setDnsConsoleOpen(true);
        setEditor(null);
        setMessage(dnsJobProgressMessage(response.job));
        setStatus(running || response.job.status === "succeeded" ? "ready" : "error");
        if (!running) {
          void loadWorkspace();
        }
      })
      .catch((error) => {
        setEditor((current) =>
          current
            ? {
                ...current,
                status: "error",
                message: barraganApiErrorSummary(error, "Could not apply DNS records.")
              }
            : current
        );
      });
  };

  const preservedRecords = editor ? dnsPreservedRecords(editor.domain, supportedTypes) : [];
  const dnsEditorBusy = editor?.status === "previewing" || editor?.status === "applying";
  const dnsConsoleText = jobConsoleText(dnsJob, message || "No DNS job events are available yet.");

  return (
    <section className="workflow-stack" aria-label="Engagement DNS">
      <section className="guided-review">
        <div className="section-heading">
          <div>
            <h3>DNS</h3>
            <p>Manage registrar DNS records for domains assigned to this engagement.</p>
          </div>
          <div className="section-actions compact-actions">
            <span>{status}</span>
            <button className="secondary-action compact" disabled={!engagementId || status === "loading"} onClick={() => void loadWorkspace()} type="button">
              Refresh
            </button>
          </div>
        </div>
        <p className="guardrail-hint">{workspace?.notice ?? "DNS records do not create inbound channels. Create inbound routes separately from Channels."}</p>
        {message ? <div className={status === "error" ? "inline-alert" : "inline-warning"} role="status">{message}</div> : null}
      </section>

      <section className="table-panel embedded operations-table engagement-dns-table" aria-label="Engagement DNS domains">
        <div className="section-heading table-section-heading">
          <div>
            <h3>Assigned domains</h3>
            <p>Record edits are previewed against live provider state before apply.</p>
          </div>
          <span>{workspace?.domains.length ?? 0} domains</span>
        </div>
        <TableHeader columns={["Domain", "Records", "Latest Snapshot", "Purpose", "Actions"]} />
        {workspace?.domains.length ? (
          workspace.domains.map((domain) => (
            <div className={`table-row domain-row ${domainRiskClassName(domain.healthRisk.status)}`} key={`dns-domain-${domain.id}`}>
              <span>
                <strong>{domain.domainName}</strong>
                <small>{domain.registrar}</small>
              </span>
              <span>{domain.dns.hosts.length} records</span>
              <span>{formatDomainDateTime(domain.dns.fetchedAt)}</span>
              <DomainPurposeTags purpose={domain.purpose} purposeTags={domain.purposeTags} />
              <span className="row-actions">
                <button className="secondary-action compact" onClick={() => openEditor(domain)} type="button">
                  Manage DNS
                </button>
              </span>
            </div>
          ))
        ) : (
          <OperationsEmptyState message="No active domains are assigned to this engagement." />
        )}
      </section>

      <section className="table-panel embedded operations-table dns-edge-targets-table" aria-label="DNS edge targets">
        <div className="section-heading table-section-heading">
          <h3>Eligible edge targets</h3>
          <span>{workspace?.edgeTargets.length ?? 0} edges</span>
        </div>
        <TableHeader columns={["Edge", "Public IP", "Provider", "Region", "Proxy", "Status"]} />
        {workspace?.edgeTargets.length ? (
          workspace.edgeTargets.map((edge) => (
            <div className="table-row" key={`dns-edge-${edge.id}`}>
              <span>{edge.hostname || edge.id}</span>
              <code>{edge.publicIp}</code>
              <span>{edge.provider || "N/A"}</span>
              <span>{edge.region || "N/A"}</span>
              <span>{edge.proxy || "N/A"}</span>
              <StatusPill value={edge.status || "unknown"} />
            </div>
          ))
        ) : (
          <OperationsEmptyState message="No deployed edge nodes with public IPs are available for A record prefill." />
        )}
      </section>

      {editor ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel dns-floating-panel" aria-label={`DNS records for ${editor.domain.domainName}`}>
            <div className="section-heading">
              <div>
                <h3>{editor.domain.domainName}</h3>
                <p>Submit the complete desired host record list. Omitted records are removed by Namecheap.</p>
              </div>
              <div className="section-actions compact-actions">
                <span>{editor.status}</span>
                {dnsJob ? (
                  <button
                    className="secondary-action compact icon-action"
                    onClick={() => {
                      setDnsConsoleCopied(false);
                      setDnsConsoleOpen(true);
                    }}
                    title="Open DNS progress console"
                    type="button"
                  >
                    <ListChecks size={14} />
                    <span>Log</span>
                  </button>
                ) : null}
                <button className="secondary-action compact" onClick={() => setEditor(null)} type="button">
                  Close
                </button>
              </div>
            </div>
            <p className="guardrail-hint">DNS changes only update host records. NS records can delegate a subdomain but do not change registrar-level nameservers. DNS changes do not create inbound channels, routes, certificates, or services.</p>
            {editor.message ? (
              <div className={editor.status === "error" ? "inline-alert" : "inline-warning"} role="status">
                {editor.message}
              </div>
            ) : null}
            {preservedRecords.length ? (
              <section className="dns-preserved-records" aria-label="Provider records preserved automatically">
                <div>
                  <h4>Provider records preserved automatically</h4>
                  <p>These record types are not editable in V1, but Barragan keeps them in the full Namecheap host list during apply.</p>
                </div>
                <DnsRecordMiniTable records={preservedRecords} />
              </section>
            ) : null}
            {editor.step === "manage" ? (
              <>
                <div className="dns-record-editor-list" aria-label="DNS record editor">
                  {editor.records.map((record, index) => {
                    const valueSuggestions = dnsValueSuggestions(record.type, workspace?.edgeTargets ?? []);
                    const valueSuggestionsId = valueSuggestions.length ? `dns-value-suggestions-${record.localId}` : undefined;
                    return (
                      <div className={`dns-record-editor-row ${record.type === "MX" ? "has-mx-pref" : ""}`} key={record.localId}>
                        <label>
                          <span>Type</span>
                          <select
                            aria-label={`DNS record type ${index + 1}`}
                            onChange={(event) => updateRecord(record.localId, { type: event.target.value })}
                            value={record.type}
                          >
                            {supportedTypes.map((type) => (
                              <option key={`dns-type-${type}`} value={type}>{type}</option>
                            ))}
                          </select>
                        </label>
                        <label>
                          <span>Host</span>
                          <input
                            aria-label={`DNS host ${index + 1}`}
                            onChange={(event) => updateRecord(record.localId, { name: event.target.value })}
                            value={record.name}
                          />
                        </label>
                        <label>
                          <span>Value</span>
                          <input
                            aria-label={`DNS value ${index + 1}`}
                            list={valueSuggestionsId}
                            onChange={(event) => updateRecord(record.localId, { address: event.target.value })}
                            value={record.address}
                          />
                          {valueSuggestionsId ? (
                            <datalist id={valueSuggestionsId}>
                              {valueSuggestions.map((suggestion) => (
                                <option key={`${record.localId}-${suggestion.value}-${suggestion.label}`} label={suggestion.label} value={suggestion.value} />
                              ))}
                            </datalist>
                          ) : null}
                        </label>
                        <label>
                          <span>TTL</span>
                          <input
                            aria-label={`DNS TTL ${index + 1}`}
                            onChange={(event) => updateRecord(record.localId, { ttl: event.target.value })}
                            value={record.ttl}
                          />
                        </label>
                        {record.type === "MX" ? (
                          <label>
                            <span>MX Pref</span>
                            <input
                              aria-label={`DNS MX preference ${index + 1}`}
                              onChange={(event) => updateRecord(record.localId, { mxPref: event.target.value })}
                              value={record.mxPref ?? "10"}
                            />
                          </label>
                        ) : null}
                        <button className="danger-action compact" onClick={() => removeRecord(record.localId)} type="button">
                          Remove
                        </button>
                      </div>
                    );
                  })}
                </div>
                <div className="form-actions">
                  <button className="secondary-action" onClick={addRecord} type="button">
                    Add Record
                  </button>
                  <button className="primary-action" disabled={dnsEditorBusy} onClick={previewDns} type="button">
                    {editor.status === "previewing" ? "Previewing Changes..." : "Apply Changes"}
                  </button>
                </div>
              </>
            ) : editor.preview ? (
              <DnsPreviewPanel
                busy={dnsEditorBusy}
                onApply={applyDns}
                onCancel={cancelDnsPreview}
                preview={editor.preview}
              />
            ) : null}
          </section>
        </div>
      ) : null}
      {dnsConsoleOpen && (dnsJob || message) ? (
        <div className="modal-scrim nested-modal-scrim" role="presentation">
          <section className="floating-panel channel-console-panel" aria-label="DNS job console">
            <div className="section-heading">
              <div>
                <h3>DNS progress console</h3>
                <ProgressConsolePrimaryLine job={dnsJob} summary={dnsJob ? dnsJobProgressMessage(dnsJob) : message || "DNS job progress."} />
              </div>
              <div className="section-actions compact-actions">
                <button
                  className="secondary-action compact"
                  disabled={!navigator.clipboard}
                  onClick={() => {
                    if (!navigator.clipboard) {
                      return;
                    }
                    void navigator.clipboard.writeText(dnsConsoleText).then(() => setDnsConsoleCopied(true));
                  }}
                  type="button"
                >
                  <Copy size={14} />
                  {dnsConsoleCopied ? "Copied" : "Copy log"}
                </button>
                <button className="secondary-action compact" onClick={() => setDnsConsoleOpen(false)} type="button">
                  Close
                </button>
              </div>
            </div>
            <pre>{dnsConsoleText}</pre>
          </section>
        </div>
      ) : null}
    </section>
  );
}

function DnsPreviewPanel({
  busy,
  onApply,
  onCancel,
  preview
}: {
  busy: boolean;
  onApply: () => void;
  onCancel: () => void;
  preview: EngagementDnsPreview;
}) {
  const { diff } = preview;
  const rows = dnsDiffRows(diff);
  const hasChanges = dnsPreviewHasChanges(preview);
  return (
    <section className="table-panel embedded operations-table dns-preview-panel" aria-label="DNS preview diff">
      <div className="section-heading table-section-heading">
        <div>
          <h3>Preview Changes</h3>
          <p>Review the exact DNS host record changes before applying them to the registrar.</p>
        </div>
        <span>{diff.added.length} add · {diff.updated.length} update · {diff.removed.length} remove</span>
      </div>
      <TableHeader columns={["Change", "Host", "Type", "Value", "TTL"]} />
      {rows.length ? (
        rows.map((row, index) => (
          <div className={`table-row dns-diff-row dns-diff-${row.kind}`} key={`dns-diff-${index}`}>
            <StatusPill value={row.kind} />
            <DnsDiffCell before={row.before?.name} after={row.after.name} highlight={row.kind === "update" && (row.before?.name || "") !== (row.after.name || "")} />
            <DnsDiffCell before={row.before?.type} after={row.after.type} highlight={row.kind === "update" && (row.before?.type || "") !== (row.after.type || "")} />
            <DnsDiffCell before={row.before?.address} after={row.after.address} code highlight={row.kind === "update" && (row.before?.address || "") !== (row.after.address || "")} />
            <DnsDiffCell before={row.before?.ttl} after={row.after.ttl} highlight={row.kind === "update" && (row.before?.ttl || "") !== (row.after.ttl || "")} />
          </div>
        ))
      ) : (
        <OperationsEmptyState message="No DNS record changes detected." />
      )}
      <div className="form-actions">
        <button className="secondary-action" disabled={busy} onClick={onCancel} type="button">
          Cancel
        </button>
        <button className="primary-action" disabled={busy || !hasChanges} onClick={onApply} type="button">
          {busy ? "Starting Apply..." : "Apply Now"}
        </button>
      </div>
    </section>
  );
}

function DnsDiffCell({
  after,
  before,
  code = false,
  highlight = false
}: {
  after?: string;
  before?: string;
  code?: boolean;
  highlight?: boolean;
}) {
  const beforeText = before || "N/A";
  const afterText = after || "N/A";
  const value = highlight ? (
    <span className="dns-diff-value-change">
      <span>{beforeText}</span>
      <span aria-hidden="true">→</span>
      <strong>{afterText}</strong>
    </span>
  ) : (
    afterText
  );
  return code ? <code className={highlight ? "dns-diff-highlight" : ""}>{value}</code> : <span className={highlight ? "dns-diff-highlight" : ""}>{value}</span>;
}

function DnsRecordMiniTable({ records }: { records: EngagementDnsRecord[] }) {
  return (
    <div className="dns-record-mini-table">
      <TableHeader columns={["Host", "Type", "Value", "TTL"]} />
      {records.length ? (
        records.map((record, index) => (
          <div className="table-row" key={`dns-record-mini-${record.name}-${record.type}-${record.address}-${index}`}>
            <span>{record.name || "@"}</span>
            <span>{record.type || "N/A"}</span>
            <code>{record.address || "N/A"}</code>
            <span>{record.ttl || "600"}</span>
          </div>
        ))
      ) : (
        <OperationsEmptyState message="No DNS records." />
      )}
    </div>
  );
}

type CapabilityPanelState = {
  status: "idle" | "loading" | "ready" | "saving" | "error";
  message: string;
  workspace: EngagementCapabilityWorkspace | null;
  draftDeselectedDefaults: CapabilitySelectionRef[];
  draftSelectedOptionals: CapabilitySelectionRef[];
  draftInferenceProxy: InferenceProxyConfiguration;
  draftAtc: AtcConfiguration;
};

type OpsecCapabilityPanelState = {
  status: "idle" | "loading" | "ready" | "applying" | "error";
  message: string;
  configuration: OpsecNetworkRestrictionsConfiguration;
  destinationsText: string;
  job: JobRunDetail | null;
};

const capabilityHostClassOrder = ["common", "homebase", "proxy", "elk"];
const staticWebCapabilityId = "barragan.static-web-site";
const customListenerCapabilityId = "barragan.custom-listener";
const backflipsCapabilityId = "barragan.backflips-v2";
const opsecCapabilityId = "opsec";
const inferenceProxyCapabilityId = "inference-proxy";

function CapabilitiesPage({
  engagementId,
  onConfigureBackflips,
  onConfigureStaticWeb,
  onConfigureCustomListener,
  staticWebActiveCount,
  customListenerActiveCount
}: {
  engagementId: string | null;
  onConfigureBackflips: () => void;
  onConfigureStaticWeb: () => void;
  onConfigureCustomListener: () => void;
  staticWebActiveCount: number;
  customListenerActiveCount: number;
}) {
  const [state, setState] = useState<CapabilityPanelState>({
    status: "idle",
    message: "",
    workspace: null,
    draftDeselectedDefaults: [],
    draftSelectedOptionals: [],
    draftInferenceProxy: defaultInferenceProxyConfiguration(),
    draftAtc: defaultAtcConfiguration()
  });
  const [activeCapability, setActiveCapability] = useState<EngagementCapabilityEntry | null>(null);
  const [opsecState, setOpsecState] = useState<OpsecCapabilityPanelState>({
    status: "idle",
    message: "",
    configuration: defaultOpsecConfiguration(),
    destinationsText: "",
    job: null
  });
  const [opsecConsoleOpen, setOpsecConsoleOpen] = useState(false);
  const [opsecConsoleCopied, setOpsecConsoleCopied] = useState(false);
  const [capabilityApplyJob, setCapabilityApplyJob] = useState<JobRunDetail | null>(null);
  const [capabilityApplyConsoleOpen, setCapabilityApplyConsoleOpen] = useState(false);
  const [capabilityApplyConsoleCopied, setCapabilityApplyConsoleCopied] = useState(false);
  const [inferenceStatus, setInferenceStatus] = useState<InferenceProxyStatus | null>(null);
  const [inferenceStatusLoading, setInferenceStatusLoading] = useState(false);
  const [inferenceStatusError, setInferenceStatusError] = useState("");
  const inferenceRequestVersion = useRef(0);

  useEffect(() => {
    const version = ++inferenceRequestVersion.current;
    setInferenceStatus(null);
    setInferenceStatusError("");
    if (!engagementId || activeCapability?.id !== inferenceProxyCapabilityId) {
      setInferenceStatusLoading(false);
      return;
    }
    setInferenceStatusLoading(true);
    apiClient.inferenceProxyStatus(engagementId).then((response) => {
      if (version !== inferenceRequestVersion.current) return;
      setInferenceStatus(response.inferenceProxyStatus);
    }).catch((error) => {
      if (version !== inferenceRequestVersion.current) return;
      setInferenceStatusError(error instanceof BarraganApiError ? error.message : "Could not load Inference Proxy status.");
    }).finally(() => {
      if (version === inferenceRequestVersion.current) setInferenceStatusLoading(false);
    });
    return () => { ++inferenceRequestVersion.current; };
  }, [engagementId, activeCapability?.id, JSON.stringify(state.workspace?.inferenceProxy?.configuration), JSON.stringify(state.workspace?.overrides.selectedOptionals)]);

  useEffect(() => {
    if (!engagementId || activeCapability?.id !== inferenceProxyCapabilityId || !inferenceStatus || inferenceStatusLoading) return;
    const version = inferenceRequestVersion.current;
    let cancelled = false;
    let pending = false;
    const handle = window.setInterval(() => {
      if (pending) return;
      pending = true;
      apiClient.inferenceProxyStatus(engagementId).then((response) => {
        if (cancelled || version !== inferenceRequestVersion.current) return;
        setInferenceStatus(response.inferenceProxyStatus);
        setInferenceStatusError("");
      }).catch((error) => {
        if (cancelled || version !== inferenceRequestVersion.current) return;
        setInferenceStatusError(error instanceof BarraganApiError ? error.message : "Could not refresh Inference Proxy status.");
      }).finally(() => { pending = false; });
    }, inferenceStatus.status === "checking" ? 3000 : 15000);
    return () => { cancelled = true; window.clearInterval(handle); };
  }, [engagementId, activeCapability?.id, inferenceStatus?.status, inferenceStatus?.job?.id, inferenceStatusLoading]);

  const checkInferenceStatus = async () => {
    if (!engagementId || !inferenceStatus?.bindingFingerprint) return;
    const version = ++inferenceRequestVersion.current;
    setInferenceStatusLoading(true);
    setInferenceStatusError("");
    try {
      const response = await apiClient.checkInferenceProxyStatus(engagementId, inferenceStatus.bindingFingerprint);
      if (version === inferenceRequestVersion.current) setInferenceStatus(response.inferenceProxyStatus);
    } catch (error) {
      if (version === inferenceRequestVersion.current) setInferenceStatusError(error instanceof BarraganApiError ? error.message : "Could not check Inference Proxy status.");
    } finally {
      if (version === inferenceRequestVersion.current) setInferenceStatusLoading(false);
    }
  };

  useEffect(() => {
    if (!engagementId) {
      setState({
        status: "idle",
        message: "Select or create an engagement before configuring capabilities.",
        workspace: null,
        draftDeselectedDefaults: [],
        draftSelectedOptionals: [],
    draftInferenceProxy: defaultInferenceProxyConfiguration(),
    draftAtc: defaultAtcConfiguration()
      });
      setCapabilityApplyJob(null);
      return;
    }
    let cancelled = false;
    setState((current) => ({ ...current, status: "loading", message: "Loading capability profile." }));
    apiClient
      .engagementCapabilities(engagementId)
      .then((response) => {
        if (cancelled) return;
        const applyState = capabilityApplyStateOf(response.capabilities);
        setState({
          status: "ready",
          message: applyState.status === "unsaved" ? "" : capabilityApplyStateMessage(applyState),
          workspace: response.capabilities,
          draftDeselectedDefaults: response.capabilities.overrides.deselectedDefaults ?? [],
          draftSelectedOptionals: response.capabilities.overrides.selectedOptionals ?? [],
          draftInferenceProxy: response.capabilities.inferenceProxy?.configuration ?? defaultInferenceProxyConfiguration(),
          draftAtc: response.capabilities.atc?.configuration ?? defaultAtcConfiguration()
        });
      })
      .catch((error) => {
        if (cancelled) return;
        setState((current) => ({
          ...current,
          status: "error",
          message: error instanceof BarraganApiError ? error.message : "Could not load capability profile."
        }));
      });
    return () => {
      cancelled = true;
    };
  }, [engagementId]);

  useEffect(() => {
    if (!engagementId || activeCapability?.id !== opsecCapabilityId) {
      return;
    }
    let cancelled = false;
    setOpsecState((current) => ({ ...current, status: "loading", message: "Loading OPSEC network restrictions." }));
    apiClient
      .opsecNetworkRestrictions(engagementId)
      .then((response) => {
        if (cancelled) return;
        setOpsecState((current) => ({
          ...current,
          status: "ready",
          message: "OPSEC network restrictions loaded.",
          configuration: response.configuration,
          destinationsText: response.configuration.destinations.join("\n"),
          job: response.service.applyJobId ? current.job : current.job
        }));
      })
      .catch((error) => {
        if (cancelled) return;
        setOpsecState((current) => ({
          ...current,
          status: "error",
          message: error instanceof BarraganApiError ? error.message : "Could not load OPSEC network restrictions."
        }));
      });
    return () => {
      cancelled = true;
    };
  }, [activeCapability?.id, engagementId]);

  useEffect(() => {
    const job = opsecState.job;
    if (!job || !["queued", "running"].includes(job.status)) {
      return;
    }
    const handle = window.setInterval(() => {
      apiClient
        .job(job.id)
        .then((response) => {
          const finished = !["queued", "running"].includes(response.job.status);
          setOpsecState((current) => ({
            ...current,
            status: finished ? (response.job.status === "succeeded" ? "ready" : "error") : "applying",
            message: opsecJobProgressMessage(response.job),
            job: response.job
          }));
        })
        .catch((error) => {
          setOpsecState((current) => ({
            ...current,
            status: "error",
            message: error instanceof BarraganApiError ? error.message : "Could not refresh OPSEC job."
          }));
        });
    }, 3000);
    return () => window.clearInterval(handle);
  }, [opsecState.job?.id, opsecState.job?.status]);

  const setCapabilityWorkspace = (workspace: EngagementCapabilityWorkspace, message: string) => {
    setState({
      status: "ready",
      message,
      workspace,
      draftDeselectedDefaults: workspace.overrides.deselectedDefaults ?? [],
      draftSelectedOptionals: workspace.overrides.selectedOptionals ?? [],
      draftInferenceProxy: workspace.inferenceProxy?.configuration ?? defaultInferenceProxyConfiguration(),
      draftAtc: workspace.atc?.configuration ?? defaultAtcConfiguration()
    });
  };

  const saveSelection = async () => {
    if (!engagementId) return;
    setState((current) => ({ ...current, status: "saving", message: "Saving and preparing capability changes." }));
    try {
      const response = await apiClient.updateEngagementCapabilities(engagementId, {
        deselectedDefaults: state.draftDeselectedDefaults,
        selectedOptionals: state.draftSelectedOptionals,
        inferenceProxy: state.draftInferenceProxy,
        atc: state.draftAtc
      });
      setCapabilityWorkspace(response.capabilities, capabilityApplyStateMessage(capabilityApplyStateOf(response.capabilities)));
    } catch (error) {
      try {
        const refreshed = await apiClient.engagementCapabilities(engagementId);
        setState((current) => ({
          ...current,
          status: "error",
          workspace: refreshed.capabilities,
          message: error instanceof BarraganApiError ? error.message : "Could not save capability selection."
        }));
      } catch {
        setState((current) => ({
          ...current,
          status: "error",
          message: error instanceof BarraganApiError ? error.message : "Could not save capability selection."
        }));
      }
    }
  };

  const applySavedChanges = async () => {
    const applyState = capabilityApplyStateOf(state.workspace);
    const retrying = ["failed", "partial"].includes(applyState.status);
    if (!engagementId || !["saved_ready", "failed", "partial"].includes(applyState.status)) {
      setState((current) => ({
        ...current,
        status: "ready",
        message: current.workspace ? capabilityApplyStateMessage(capabilityApplyStateOf(current.workspace)) : "Save capability changes before applying them to running infrastructure."
      }));
      return;
    }
    setState((current) => ({
      ...current,
      status: "saving",
      message: retrying ? "Retrying saved capability changes." : "Starting saved capability changes."
    }));
    try {
      const response = await apiClient.applyEngagementCapabilities(engagementId);
      setCapabilityApplyJob(response.capabilityApply.job);
      setCapabilityApplyConsoleCopied(false);
      setCapabilityApplyConsoleOpen(false);
      setState((current) => ({
        ...current,
        status: "ready",
        message: capabilityApplyStateMessage(response.capabilityApply.applyState),
        workspace: current.workspace ? { ...current.workspace, applyState: response.capabilityApply.applyState } : current.workspace
      }));
    } catch (error) {
      try {
        const refreshed = await apiClient.engagementCapabilities(engagementId);
        setCapabilityWorkspace(refreshed.capabilities, capabilityApplyStateMessage(capabilityApplyStateOf(refreshed.capabilities)));
      } catch {
        setState((current) => ({
          ...current,
          status: "error",
          message: error instanceof BarraganApiError ? error.message : "Could not start the saved capability apply."
        }));
      }
    }
  };

  const toggleCapability = (entry: EngagementCapabilityEntry) => {
    if (entry.locked || !entry.operator?.selectable) return;
    if (entry.id === staticWebCapabilityId && state.workspace?.nativeState?.staticWeb?.claimed) return;
    if (entry.classification === "default") {
      setState((current) => ({
        ...current,
        draftDeselectedDefaults: toggleSelectionRow(current.draftDeselectedDefaults, { hostClass: entry.hostClass, id: entry.id })
      }));
    } else if (entry.classification === "optional") {
      setState((current) => ({
        ...current,
        draftSelectedOptionals: toggleSelectionRow(current.draftSelectedOptionals, { hostClass: entry.hostClass, id: entry.id })
      }));
    }
  };

  const applyOpsecRestrictions = async () => {
    if (!engagementId) return;
    const destinations = opsecState.destinationsText
      .split(/\r?\n|,/)
      .map((value) => value.trim())
      .filter(Boolean);
    setOpsecState((current) => ({ ...current, status: "applying", message: "Applying OPSEC network restrictions." }));
    setOpsecConsoleCopied(false);
    try {
      const response = await apiClient.applyOpsecNetworkRestrictions(engagementId, {
        enabled: opsecState.configuration.enabled,
        destinations,
        notes: opsecState.configuration.notes,
        purpose: opsecState.configuration.purpose
      });
      setOpsecState((current) => ({
        ...current,
        status: response.job.status === "failed" ? "error" : ["queued", "running"].includes(response.job.status) ? "applying" : "ready",
        message: opsecJobProgressMessage(response.job),
        configuration: response.configuration,
        destinationsText: response.configuration.destinations.join("\n"),
        job: response.job
      }));
      setOpsecConsoleOpen(true);
    } catch (error) {
      setOpsecState((current) => ({
        ...current,
        status: "error",
        message: error instanceof BarraganApiError ? error.message : "Could not apply OPSEC network restrictions."
      }));
    }
  };

  const workspace = state.workspace;
  const profile = workspace?.profileResolution;
  const hostClasses = profile?.hostClasses ?? {};
  const changed = !sameSelectionRows(state.draftDeselectedDefaults, workspace?.overrides.deselectedDefaults ?? []) ||
    !sameSelectionRows(state.draftSelectedOptionals, workspace?.overrides.selectedOptionals ?? []) ||
    JSON.stringify(state.draftInferenceProxy) !== JSON.stringify(workspace?.inferenceProxy?.configuration ?? defaultInferenceProxyConfiguration()) ||
    JSON.stringify(state.draftAtc) !== JSON.stringify(workspace?.atc?.configuration ?? defaultAtcConfiguration());
  const applyState = capabilityApplyStateOf(workspace);
  const busy = ["loading", "saving"].includes(state.status);
  const opsecBusy = ["loading", "applying"].includes(opsecState.status);
  const opsecConsoleAvailable = Boolean(opsecState.job || opsecState.message);
  const opsecConsoleLog = opsecConsoleText(opsecState.job, opsecState.message || "No OPSEC job events are available yet.");
  const capabilityApplyBusy = applyState.status === "applying";
  const capabilityApplyRetryable = ["saved_ready", "failed", "partial"].includes(applyState.status);
  const capabilityApplyConsoleAvailable = Boolean(capabilityApplyJob);
  const capabilityApplyConsoleLog = jobConsoleText(
    capabilityApplyJob,
    state.message || "No saved capability apply events are available yet."
  );
  const capabilityWorkflowStatus = state.status === "loading"
    ? "Loading"
    : state.status === "saving"
      ? "Saving and preparing"
      : state.status === "error"
        ? "Needs attention"
        : changed
          ? "Unsaved changes"
          : capabilityApplyStatusLabel(applyState.status);

  useEffect(() => {
    const jobId = applyState.parentJobId;
    if (!jobId || capabilityApplyJob?.id === jobId) {
      return;
    }
    let cancelled = false;
    apiClient.job(jobId).then((response) => {
      if (!cancelled) setCapabilityApplyJob(response.job);
    }).catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [applyState.parentJobId, capabilityApplyJob?.id]);

  useEffect(() => {
    const job = capabilityApplyJob;
    if (!engagementId || !job || !["queued", "running"].includes(job.status)) {
      return;
    }
    const refresh = () => {
      void Promise.all([apiClient.job(job.id), apiClient.engagementCapabilities(engagementId)])
        .then(([jobResponse, workspaceResponse]) => {
          setCapabilityApplyJob(jobResponse.job);
          setCapabilityWorkspace(workspaceResponse.capabilities, capabilityApplyStateMessage(capabilityApplyStateOf(workspaceResponse.capabilities)));
        })
        .catch(() => undefined);
    };
    refresh();
    const handle = window.setInterval(refresh, 3000);
    return () => window.clearInterval(handle);
  }, [capabilityApplyJob?.id, capabilityApplyJob?.status, engagementId]);

  return (
    <section className="workflow-stack" aria-label="Capabilities">
      <section className="guided-review">
        <div className="section-heading">
          <div>
            <h3>Capabilities</h3>
            <p>Select and configure supported host behavior and infrastructure prerequisites.</p>
          </div>
          <div className="section-actions compact-actions">
            <span>{capabilityWorkflowStatus}</span>
            <button className="secondary-action compact" disabled={busy || !engagementId || !changed} onClick={() => void saveSelection()} type="button">
              Save capability changes
            </button>
            <button
              className="primary-action compact"
              disabled={busy || capabilityApplyBusy || changed || !engagementId || !capabilityApplyRetryable}
              onClick={() => void applySavedChanges()}
              type="button"
            >
              {capabilityApplyBusy ? "Applying saved changes…" : ["failed", "partial"].includes(applyState.status) ? "Retry saved changes" : "Apply saved changes"}
            </button>
            {capabilityApplyConsoleAvailable ? (
              <button
                className="secondary-action compact icon-action"
                onClick={() => {
                  setCapabilityApplyConsoleCopied(false);
                  setCapabilityApplyConsoleOpen(true);
                }}
                type="button"
              >
                <ListChecks size={14} />
                <span>Log</span>
              </button>
            ) : null}
          </div>
        </div>
        <p className="guardrail-hint">
          Save prepares the selected capability inputs. Apply saved changes updates running infrastructure without Terraform or provider changes. If an apply fails, the core hosts remain running and may continue to incur provider charges; review the log, retry saved changes, or use Infrastructure to tear down the engagement explicitly.
        </p>
        {state.message ? (
          <div
            className={state.status === "error" || ["blocked", "partial", "failed"].includes(applyState.status) ? "inline-error" : ["saved_ready", "applying", "applied"].includes(applyState.status) ? "inline-success" : "inline-warning"}
            role="status"
          >
            {state.message}
          </div>
        ) : null}
        {applyState.children.length ? (
          <div className="guardrail-hint" role="status">
            {applyState.children.map((child) => `${capabilityApplyChildLabel(child.kind)}: ${capabilityApplyChildStatusLabel(child.status)}${child.detail ? ` — ${child.detail}` : ""}`).join(" · ")}
          </div>
        ) : null}
        {profile ? (
          <div className="capability-profile-grid">
            <div>
              <span>Profile</span>
              <strong>{profile.profile.name}</strong>
            </div>
            <div>
              <span>Status</span>
              <strong>{profile.status}</strong>
            </div>
            <div>
              <span>Catalog-backed</span>
              <strong>{profile.summary.catalog ?? 0}/{profile.summary.total ?? 0}</strong>
            </div>
            <div>
              <span>Deselected defaults</span>
              <strong>{state.draftDeselectedDefaults.length}</strong>
            </div>
          </div>
        ) : null}
      </section>

      {profile ? (
        capabilityHostClassOrder
          .filter((hostClass) => hostClasses[hostClass])
          .map((hostClass) => (
            <section className="guided-review" key={`capability-host-${hostClass}`}>
              <div className="section-heading">
                <h3>{capabilityHostClassLabel(hostClass)}</h3>
                <span>{capabilityHostClassCount(hostClasses[hostClass])} capabilities</span>
              </div>
              <div className="capability-list">
                {capabilityHostClassEntries(hostClasses[hostClass]).map((entry) => {
                  const effectiveSelected = capabilityEntrySelected(entry, state.draftDeselectedDefaults, state.draftSelectedOptionals);
                  const staticWebClaimed = entry.id === staticWebCapabilityId && Boolean(state.workspace?.nativeState?.staticWeb?.claimed);
                  const configurableOnly = [staticWebCapabilityId, customListenerCapabilityId, backflipsCapabilityId].includes(entry.id);
                  const selectable = Boolean(entry.operator?.selectable) && !entry.locked && !staticWebClaimed;
                  const configurationState = entry.id === staticWebCapabilityId
                    ? staticWebActiveCount
                      ? `${staticWebActiveCount} configured site${staticWebActiveCount === 1 ? "" : "s"}`
                      : "No sites configured"
                    : entry.id === customListenerCapabilityId
                      ? customListenerActiveCount
                        ? `${customListenerActiveCount} configured listener${customListenerActiveCount === 1 ? "" : "s"}`
                        : "No listeners configured"
                      : "";
                  return (
                    <div
                      className={`capability-choice ${configurableOnly ? "configurable-only" : ""} ${entry.locked ? "locked" : ""} ${effectiveSelected ? "selected" : ""}`}
                      key={`${hostClass}-${entry.classification}-${entry.id}`}
                    >
                      {!configurableOnly ? <input
                        aria-label={`${effectiveSelected ? "Disable" : "Enable"} ${entry.name}`}
                        checked={effectiveSelected}
                        disabled={!selectable || busy}
                        onChange={() => toggleCapability(entry)}
                        type="checkbox"
                      /> : null}
                      <button
                        aria-label={configurableOnly ? `Configure ${entry.name}` : undefined}
                        className="capability-choice-body"
                        onClick={() => {
                          if (entry.id === staticWebCapabilityId) onConfigureStaticWeb();
                          else if (entry.id === customListenerCapabilityId) onConfigureCustomListener();
                          else if (entry.id === backflipsCapabilityId) onConfigureBackflips();
                          else setActiveCapability(entry);
                        }}
                        type="button"
                      >
                        <span className="capability-choice-title">
                          <strong>{entry.name}</strong>
                          <small>{configurableOnly ? "configure" : capabilityChoiceLabel(entry, effectiveSelected)}</small>
                        </span>
                        <span>{entry.description || "No description provided."}</span>
                        {staticWebClaimed ? <small>{state.workspace?.nativeState?.staticWeb?.reason}</small> : null}
                        {configurationState ? <small>{configurationState}</small> : null}
                        {entry.id === backflipsCapabilityId ? (
                          <small>{state.workspace?.nativeState?.backflips?.proxies.map((proxy) => `${proxy.proxyId}: ${proxy.status}`).join(" · ") || "No eligible proxies"}</small>
                        ) : null}
                      </button>
                    </div>
                  );
                })}
                {capabilityHostClassCount(hostClasses[hostClass]) === 0 ? (
                  <OperationsEmptyState message="No capabilities are available for this host class." />
                ) : null}
              </div>
            </section>
          ))
      ) : (
        <section className="empty-state">
          <h3>No capability profile loaded</h3>
          <p>{state.message || "Open an engagement to review capabilities."}</p>
        </section>
      )}
      {activeCapability ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel service-floating-panel" aria-label={`Configure ${activeCapability.name}`}>
            <div className="section-heading">
              <div>
                <h3>{activeCapability.name}</h3>
                <p>{capabilityHostClassLabel(activeCapability.hostClass)} capability</p>
              </div>
              <div className="section-actions compact-actions">
                <span>{capabilityChoiceLabel(activeCapability, capabilityEntrySelected(activeCapability, state.draftDeselectedDefaults, state.draftSelectedOptionals))}</span>
                <button className="secondary-action compact" onClick={() => setActiveCapability(null)} type="button">
                  Close
                </button>
              </div>
            </div>
            <p className="guardrail-hint">{activeCapability.description || "No description provided."}</p>
            {activeCapability.id === opsecCapabilityId ? (
              <>
                <p>
                  Define destinations that Homebase must not contact directly. Apply renders a Homebase-only Ansible workspace and manages only rules marked with Barragan's OPSEC comment.
                </p>
                <div className="section-actions compact-actions">
                  {opsecConsoleAvailable ? (
                    <button
                      className="secondary-action compact icon-action"
                      onClick={() => {
                        setOpsecConsoleCopied(false);
                        setOpsecConsoleOpen(true);
                      }}
                      title="Open OPSEC progress console"
                      type="button"
                    >
                      <ListChecks size={14} />
                      <span>Log</span>
                    </button>
                  ) : null}
                </div>
                {opsecState.message ? (
                  <div className={opsecState.status === "error" ? "inline-error" : "inline-warning"} role="status">
                    {opsecState.message}
                  </div>
                ) : null}
                <label className="checkbox-row">
                  <input
                    aria-label="Enable OPSEC network restrictions"
                    checked={opsecState.configuration.enabled}
                    disabled={opsecBusy}
                    onChange={(event) =>
                      setOpsecState((current) => ({
                        ...current,
                        configuration: { ...current.configuration, enabled: event.target.checked }
                      }))
                    }
                    type="checkbox"
                  />
                  <span>
                    <strong>Enable Homebase outbound blocks</strong>
                    <small>When disabled, Apply removes Barragan-managed OPSEC rules and leaves other iptables rules alone.</small>
                  </span>
                </label>
                <div className="service-form-grid">
                  <label className="wide-field">
                    <span>Blocked destinations</span>
                    <textarea
                      aria-label="OPSEC blocked destinations"
                      disabled={opsecBusy}
                      onChange={(event) => setOpsecState((current) => ({ ...current, destinationsText: event.target.value }))}
                      placeholder={"10.10.0.0/16\n203.0.113.7\n2001:db8::/32"}
                      value={opsecState.destinationsText}
                    />
                    <small>Enter IPv4, IPv6, or CIDR values, one per line or comma-separated.</small>
                  </label>
                  <label className="wide-field">
                    <span>Purpose</span>
                    <input
                      aria-label="OPSEC purpose"
                      disabled={opsecBusy}
                      onChange={(event) =>
                        setOpsecState((current) => ({
                          ...current,
                          configuration: { ...current.configuration, purpose: event.target.value }
                        }))
                      }
                      placeholder="Avoid direct Homebase traffic to client ranges"
                      value={opsecState.configuration.purpose}
                    />
                  </label>
                  <label className="wide-field">
                    <span>Notes</span>
                    <textarea
                      aria-label="OPSEC notes"
                      disabled={opsecBusy}
                      onChange={(event) =>
                        setOpsecState((current) => ({
                          ...current,
                          configuration: { ...current.configuration, notes: event.target.value }
                        }))
                      }
                      placeholder="Context for operators reviewing this restriction later"
                      value={opsecState.configuration.notes}
                    />
                  </label>
                </div>
                <div className="form-actions">
                  <button
                    className="primary-action"
                    disabled={opsecBusy || !engagementId}
                    onClick={() => void applyOpsecRestrictions()}
                    type="button"
                  >
                    {opsecState.status === "applying" ? "Applying..." : "Apply OPSEC Restrictions"}
                  </button>
                </div>
              </>
            ) : activeCapability.id === "atc" ? (
              <AtcSettings
                configuration={state.draftAtc}
                onChange={(configuration) => setState((current) => ({ ...current, draftAtc: configuration }))}
                disabled={busy || capabilityApplyBusy}
                selected={capabilityEntrySelected(activeCapability, state.draftDeselectedDefaults, state.draftSelectedOptionals)}
                onToggle={() => toggleCapability(activeCapability)}
                onSave={() => void saveSelection()}
                saving={state.status === "saving"}
                changed={changed}
              />
            ) : activeCapability.id === inferenceProxyCapabilityId ? (
              <InferenceProxySettings
                configuration={state.draftInferenceProxy}
                onChange={(configuration) => setState((current) => ({ ...current, draftInferenceProxy: configuration }))}
                disabled={busy || capabilityApplyBusy}
                selected={capabilityEntrySelected(activeCapability, state.draftDeselectedDefaults, state.draftSelectedOptionals)}
                onToggle={() => toggleCapability(activeCapability)}
                onSave={() => void saveSelection()}
                saving={state.status === "saving"}
                changed={changed}
                serviceStatus={inferenceStatus}
                statusLoading={inferenceStatusLoading}
                statusError={inferenceStatusError}
                onCheck={() => void checkInferenceStatus()}
              />
            ) : (
              <>
                <p>
                  Manage this role from its selection in the capability list. Select it to include it in saved capability changes, then apply those changes to running infrastructure.
                </p>
                {activeCapability.id === "c2-observer" ? (
                  <div className="notice-panel">
                    <p>Installs C2 Observer command-line tools on Homebase. It does not start collection, schedule a worker, or send evidence to ATC.</p>
                    <p>After Apply, use the Homebase CLI with protected source credentials when you are ready. Local health checks verify the installation, not connectivity to your C2 server or ATC. Disabling this selection does not remove installed tools or saved evidence.</p>
                  </div>
                ) : null}
                {activeCapability.operator?.selectable && !activeCapability.locked ? (
                  <div className="form-actions">
                    <button
                      className="secondary-action"
                      disabled={busy}
                      onClick={() => toggleCapability(activeCapability)}
                      type="button"
                    >
                      {capabilityEntrySelected(activeCapability, state.draftDeselectedDefaults, state.draftSelectedOptionals) ? "Disable Capability" : "Enable Capability"}
                    </button>
                  </div>
                ) : null}
              </>
            )}
          </section>
        </div>
      ) : null}
      {opsecConsoleOpen && opsecConsoleAvailable ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel channel-console-panel" aria-label="OPSEC job console">
            <div className="section-heading">
              <div>
                <h3>OPSEC progress console</h3>
                <ProgressConsolePrimaryLine job={opsecState.job} summary={opsecState.message || "OPSEC network restriction job progress."} />
              </div>
              <div className="section-actions compact-actions">
                <button
                  className="secondary-action compact"
                  disabled={!navigator.clipboard}
                  onClick={() => {
                    if (!navigator.clipboard) {
                      return;
                    }
                    void navigator.clipboard.writeText(opsecConsoleLog).then(() => setOpsecConsoleCopied(true));
                  }}
                  type="button"
                >
                  <Copy size={14} />
                  {opsecConsoleCopied ? "Copied" : "Copy log"}
                </button>
                <button className="secondary-action compact" onClick={() => setOpsecConsoleOpen(false)} type="button">
                  Close
                </button>
              </div>
            </div>
            <pre>{opsecConsoleLog}</pre>
          </section>
        </div>
      ) : null}
      {capabilityApplyConsoleOpen && capabilityApplyConsoleAvailable ? (
        <div className="modal-scrim" role="presentation">
          <section className="floating-panel channel-console-panel" aria-label="Capability apply console">
            <div className="section-heading">
              <div>
                <h3>Capability apply progress</h3>
                <ProgressConsolePrimaryLine job={capabilityApplyJob} summary={state.message || "Saved capability apply progress."} />
              </div>
              <div className="section-actions compact-actions">
                <button
                  className="secondary-action compact"
                  disabled={!navigator.clipboard}
                  onClick={() => {
                    if (!navigator.clipboard) return;
                    void navigator.clipboard.writeText(capabilityApplyConsoleLog).then(() => setCapabilityApplyConsoleCopied(true));
                  }}
                  type="button"
                >
                  <Copy size={14} />
                  {capabilityApplyConsoleCopied ? "Copied" : "Copy log"}
                </button>
                <button className="secondary-action compact" onClick={() => setCapabilityApplyConsoleOpen(false)} type="button">Close</button>
              </div>
            </div>
            <pre>{capabilityApplyConsoleLog}</pre>
          </section>
        </div>
      ) : null}
    </section>
  );
}

export function dashboardResponseIsComplete(dashboard: DashboardInventory | null): dashboard is DashboardInventory {
  const health = dashboard?.systemHealth;
  const checks = health ? [health.api, health.database, health.disk, health.providers] : [];
  return Boolean(
    dashboard?.generatedAt &&
    dashboard.engagementOverview &&
    Array.isArray(dashboard.engagementOverview.active) &&
    Array.isArray(dashboard.engagementOverview.recentlyEnded) &&
    Array.isArray(dashboard.engagementOverview.recentlyArchived) &&
    checks.length === 4 &&
    checks.every((check) => Boolean(check?.status && check.status !== "loading" && check.detail && check.detail !== "Loading"))
  );
}

export function KeyedEdgeAppendReview({ engagementId, chain }: {
  engagementId: string;
  chain: SketchChainRecord;
}) {
  const [review, setReview] = useState<KeyedEdgeAppendPlanReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    let active = true;
    const refresh = () => apiClient.keyedEdgeAppendPlanReview(engagementId, chain.chainId)
      .then(({ review: next }) => { if (active) setReview(next); })
      .catch(() => { if (active) setMessage("Append plan review is unavailable."); });
    void refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [engagementId, chain.chainId]);

  if (!review?.available) return null;
  const run = (operation: () => Promise<{ review: KeyedEdgeAppendPlanReview }>) => {
    setBusy(true);
    setMessage("");
    operation().then(({ review: next }) => setReview(next))
      .catch(() => setMessage("Could not change the append plan review. Check the job and try again."))
      .finally(() => setBusy(false));
  };
  return (
    <div className="workflow-actions" role="group" aria-label={`${chain.chainId} DevTest append review`}>
      {review.status === "ready" ? (
        <button className="secondary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.createKeyedEdgeAppendPlanReview(
            engagementId, chain.chainId))}
          type="button">Review one edge append</button>
      ) : null}
      {review.status !== "ready" ? (
        <span role="status">DevTest append review: {review.planStatus || review.status}
          {review.applyRequested ? " · applying reviewed plan" : ""}
          {review.newEdgeAddress ? ` · ${review.newEdgeAddress}` : ""}
          {review.planSha256 ? ` · plan ${review.planSha256.slice(0, 12)}` : ""}</span>
      ) : null}
      {review.failedReviewDiscardState === "waiting" ? (
        <span role="status">Waiting for the review worker claim to expire before safe discard.</span>
      ) : null}
      {review.failedReviewDiscardState === "ready" ? (
        <button className="secondary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.discardKeyedEdgeAppendPlanReview(
            engagementId, chain.chainId))} type="button">Discard failed review</button>
      ) : null}
      {review.unscheduledReviewCancelState === "waiting" ? (
        <span role="status">Waiting briefly to confirm the append review worker did not start.</span>
      ) : null}
      {review.unscheduledReviewCancelState === "ready" ? (
        <button className="secondary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.discardKeyedEdgeAppendPlanReview(
            engagementId, chain.chainId))} type="button">Cancel unstarted review</button>
      ) : null}
      {review.failedApplyRecoveryState === "waiting" ? (
        <span role="status">Waiting for the Apply worker claim to expire before recovery.</span>
      ) : null}
      {review.failedApplyRecoveryState === "ready" ? (
        <button className="secondary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.recoverNoGoKeyedEdgeAppendApply(
            engagementId, chain.chainId))} type="button">Recover unstarted edge Apply</button>
      ) : null}
      {review.publicationRecoveryState === "waiting" ? (
        <span role="status">Waiting for the completed edge job claim to expire before publication recovery.</span>
      ) : null}
      {review.publicationRecoveryState === "ready" ? (
        <button className="secondary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.recoverKeyedEdgeAppendPublication(
            engagementId, chain.chainId))} type="button">Resume proved edge publication</button>
      ) : null}
      {review.applyAvailable && review.planSha256 ? (
        <button className="primary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.applyKeyedEdgeAppendPlanReview(
            engagementId, chain.chainId, review.planSha256!))}
          type="button">Apply reviewed edge plan</button>
      ) : null}
      {review.status === "awaiting_apply" && !review.applyRequested ? (
        <button className="secondary-action compact" disabled={busy}
          onClick={() => run(() => apiClient.discardKeyedEdgeAppendPlanReview(
            engagementId, chain.chainId))} type="button">Discard review</button>
      ) : null}
      {message ? <span role="alert">{message}</span> : null}
    </div>
  );
}

export function MixedAppendReview({ engagementId, chains, catalogs }: {
  engagementId: string;
  chains: SketchChainRecord[];
  catalogs: Record<string, SketchProviderCatalog>;
}) {
  const digitalocean = chains.find((chain) => chain.middleProvider === "digitalocean" && chain.edgeProvider === "digitalocean");
  const linode = chains.find((chain) => chain.middleProvider === "linode" && chain.edgeProvider === "linode");
  const [review, setReview] = useState<MixedAppendPlanReview | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [digitaloceanRegion, setDigitaloceanRegion] = useState(digitalocean?.edgeRegion ?? "");
  const [linodeRegion, setLinodeRegion] = useState(linode?.edgeRegion ?? "");

  useEffect(() => {
    let active = true;
    const refresh = () => apiClient.mixedAppendPlanReview(engagementId)
      .then(({ review: next }) => { if (active) setReview(next); })
      .catch(() => { if (active) setMessage("Paired edge review is unavailable."); });
    void refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [engagementId]);

  if (!digitalocean || !linode || !review?.available) return null;
  const run = (operation: () => Promise<{ review: MixedAppendPlanReview }>) => {
    setBusy(true);
    setMessage("");
    operation().then(({ review: next }) => setReview(next))
      .catch((error) => setMessage(barraganApiErrorSummary(error, "Could not change the paired edge review. Check the job and try again.")))
      .finally(() => setBusy(false));
  };
  const choices: MixedAppendEdgeChoices = {
    digitalocean: { selectedChainId: linode.chainId, edgeRegion: digitaloceanRegion, edgeSize: digitalocean.edgeSize },
    linode: { selectedChainId: digitalocean.chainId, edgeRegion: linodeRegion, edgeType: linode.edgeSize }
  };
  const inheritedSize = catalogs.digitalocean?.sizes.find((size) => size.id === digitalocean.edgeSize);
  const compatibleDigitaloceanRegions = new Set(inheritedSize?.available ? inheritedSize.regions ?? [] : []);
  const updateStarted = Boolean(review.applyStage) || ["apply_sealed", "attention"].includes(review.status);
  const reviewStatusLabel = review.applyStage || (updateStarted
    ? "awaiting progress"
    : review.planStatus === "succeeded" ? "ready for review" : review.planStatus || review.status);
  const digitaloceanRegionAvailable = compatibleDigitaloceanRegions.has(digitaloceanRegion)
    && catalogs.digitalocean?.regions.some((region) => region.id === digitaloceanRegion && region.available);
  const availabilityMessage = !inheritedSize || !inheritedSize.available || !compatibleDigitaloceanRegions.size
    ? "DigitalOcean compatibility information is unavailable. Refresh the provider catalog before reviewing."
    : !digitaloceanRegionAvailable
      ? "The selected DigitalOcean region does not offer the inherited edge size. Choose a compatible region."
      : "";
  return (
    <section className="workflow-panel mixed-append-review" aria-label="Paired cross-provider edge append">
      <div className="section-heading">
        <div>
          <h3>Add cross-provider edges</h3>
          <p>Add one DigitalOcean edge through the Linode middle and one Linode edge through the DigitalOcean middle. Existing nodes stay in place.</p>
          <p>Review these edge additions before configuring independent channels, services, DNS or certificates.</p>
        </div>
        {review.parentJobId ? <span>Job {review.parentJobId}</span> : null}
      </div>
      {review.status === "ready" ? (
        <div className="detail-grid">
          <label>
            <span>DigitalOcean edge region · via {linode.chainId}</span>
            <select aria-label="DigitalOcean append edge region" value={digitaloceanRegion} onChange={(event) => setDigitaloceanRegion(event.target.value)}>
              {regionOptions(catalogs, "digitalocean", digitaloceanRegion).map((region) => (
                <option disabled={!region.available || !compatibleDigitaloceanRegions.has(region.id)} key={region.id} value={region.id}>{region.label}{!compatibleDigitaloceanRegions.has(region.id) ? " · size unavailable" : ""}</option>
              ))}
            </select>
          </label>
          <label>
            <span>Linode edge region · via {digitalocean.chainId}</span>
            <select value={linodeRegion} onChange={(event) => setLinodeRegion(event.target.value)}>
              {regionOptions(catalogs, "linode", linodeRegion).map((region) => (
                <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>
              ))}
            </select>
          </label>
          {availabilityMessage ? <p role="status">{availabilityMessage}</p> : null}
          <span>Existing edge sizes: DigitalOcean {digitalocean.edgeSize}; Linode {linode.edgeSize}</span>
        </div>
      ) : null}
      {review.reviewSummary ? (
        <div className="detail-grid" aria-label="Paired edge plan summary">
          {review.reviewSummary.plans.map((plan) => (
            <div key={plan.provider}>
              <span>{plan.provider === "digitalocean" ? "DigitalOcean" : "Linode"} edge</span>
              <strong>{plan.edgeRegion} · {plan.edgeSizeOrType} · via {plan.selectedChainId}</strong>
              <p>Terraform adds {plan.newEdgeAddress}; plan {plan.savedPlanSha256.slice(0, 12)}</p>
            </div>
          ))}
          <p>{review.reviewSummary.outcome}</p>
        </div>
      ) : null}
      <div className="workflow-actions">
        {review.status === "ready" ? (
          <button className="secondary-action compact" disabled={busy || !digitaloceanRegionAvailable || !linodeRegion}
            onClick={() => run(() => apiClient.createMixedAppendPlanReview(engagementId, choices))}
            type="button">Review both edge additions</button>
        ) : null}
        {review.status !== "ready" ? (
          <span role="status">Paired edge {updateStarted ? "update" : "plan"}: {reviewStatusLabel}
            {review.reviewSha256 ? ` · review ${review.reviewSha256.slice(0, 12)}` : ""}</span>
        ) : null}
        {review.retryAvailable && review.retryChoices ? (
          <button className="secondary-action compact" disabled={busy}
            onClick={() => run(() => apiClient.createMixedAppendPlanReview(engagementId, review.retryChoices!))}
            type="button">Retry Review</button>
        ) : null}
        {review.proofResumeAvailable ? (
          <p>Provider changes completed. Resume verification to continue.</p>
        ) : null}
        {review.proofResumeAvailable && review.reviewSha256 ? (
          <button className="primary-action compact" disabled={busy}
            onClick={() => run(() => apiClient.applyMixedAppendPlanReview(engagementId, review.reviewSha256!))}
            type="button">Resume proof</button>
        ) : null}
        {review.applyAvailable && review.reviewSha256 ? (
          <button className="primary-action compact" disabled={busy}
            onClick={() => run(() => apiClient.applyMixedAppendPlanReview(engagementId, review.reviewSha256!))}
            type="button">Apply both reviewed edge additions</button>
        ) : null}
      </div>
      {review.attention ? <p className="inline-warning" role="alert">Paired edge Apply needs attention. Open the job for its last proved step; Barragan will not repeat an uncertain provider write.</p> : null}
      {message ? <span role="alert">{message}</span> : null}
    </section>
  );
}

function Content({
  activeView,
  activeGlobalSettingsTab,
  activeEngagementTab,
  currentUser,
  isAdministrator,
  credentialForm,
  credentialMessage,
  credentials,
  credentialsStatus,
  digitalOceanPreflightAction,
  digitalOceanProviderSmokeAction,
  data,
  engagementOperations,
  engagementOperationsStatus,
  engagementWorkspace,
  engagementWorkspaceStatus,
  engagementWorkflowRevision,
  engagementWorkflowStatus,
  backflipsServiceAction,
  desktopServiceAction,
  genericServiceAction,
  genericServiceForm,
  webStaticServiceAction,
  webStaticServiceForm,
  webStaticServiceRemovalAction,
  guidedBackflipEnabled,
  guidedDeploymentInput,
  guidedEngagementName,
  guidedOperators,
  guidedOperatorsList,
  guidedSshEnabled,
  housekeepingItemsDraft,
  infrastructureConsoleOpen,
  jobsPagination,
  jobsStatus,
  inboundChannelAction,
  inboundChannelDraft,
  linodeSketchChain,
  linodeSketchRunJob,
  linodeSketchRunStatus,
  deployableInitialSketchChains,
  sketchDeploymentJobs,
  outboundChannelAction,
  outboundChannelDraft,
  sketchSshKey,
  sketchSshKeyStatus,
  sketchSshKeyRemovalAction,
  sketchSshKeyRotationAction,
  sketchChainRecords,
  sketchChainRecordsStatus,
  sketchChainMessage,
  sketchChainCancelTarget,
  sketchChainCancelConfirmation,
  sketchChainPowerConfirmations,
  sketchEdgeTransitionConfirmations,
  sketchEdgeReplacementRegions,
  sketchChainTeardownTarget,
  sketchChainTeardownConfirmation,
  sketchIntent,
  observerSettings,
  observerForbiddenPortsInput,
  observerCheckAction,
  onChangePassword,
  onSignOut,
  onSignOutAll,
  onArchiveEngagement,
  onCompileSelectedRevision,
  onCreateCredential,
  onCreateEngagement,
  onDeleteEngagement,
  onReconcileEngagement,
  onDisableCredential,
  onRunDigitalOceanSketchPreflight,
  onRunDigitalOceanProviderSmokeValidation,
  onEditEngagement,
  onRefreshCredentials,
  onRefreshProviderRegionPolicies,
  onEnsureProviderCatalogs,
  onUpdateProviderRegionPolicy,
  onUpdateObserverSettingsDraft,
  onSaveObserverSettings,
  onEnsureInspectorReadiness,
  onRunObserverCheck,
  onInspectorCleanupComplete,
  onRefreshLinodeSketchRun,
  onLoadSelectedRevisions,
  onLoadJobsPage,
  onOpenEngagementWorkspace,
  onPrepareEngagementWorkspace,
  onRunTestDeployment,
  onRecordChannels,
  onRecoverProviderOrphan,
  onOpenLifecycleConsole,
  onRefreshDashboardProviderInventory,
  onSetProviderOrphanTeardownConfirmation,
  onCreateInboundChannel,
  onEditInboundChannel,
  onDisableInboundChannel,
  onRemoveInboundChannel,
  onRecoverInboundChannel,
  onSaveHousekeepingItems,
  onPreviewInboundChannelApply,
  onApplyInboundChannel,
  onValidateInboundChannel,
  onUpdateInboundChannelConfirmation,
  onRefreshEngagementOperations,
  onPreviewOutboundChannelApply,
  onApplyOutboundChannel,
  onValidateOutboundChannel,
  onUpdateOutboundChannelConfirmation,
  onPreviewBackflipsServiceApply,
  onApplyBackflipsService,
  onUpdateBackflipsServiceAction,
  backflipsConsoleOpen,
  backflipsConsoleCopied,
  setBackflipsConsoleOpen,
  setBackflipsConsoleCopied,
  onApplyDesktopService,
  onPreviewWebStaticServiceApply,
  onApplyWebStaticService,
  onRestoreWebStaticService,
  onPreviewWebStaticServiceRemove,
  onApplyWebStaticServiceRemove,
  onUpdateWebStaticServiceForm,
  onResetWebStaticServiceAction,
  onUpdateWebStaticServiceRemovalAction,
  onSaveGenericService,
  onDisableGenericService,
  onRestoreGenericService,
  onRemoveGenericService,
  onUpdateGenericServiceForm,
  onUpdateGenericServiceAction,
  onRefreshTestDeploymentRun,
  onRenderSelectedRevision,
  onBeginTestDeploymentTeardown,
  onTeardownTestDeploymentRun,
  onRotateCredential,
  onResumePilotRunFromJob,
  onSelectJob,
  onSetDefaultCredential,
  onValidateCredential,
  onGenerateSketchSshKey,
  onDownloadSketchSshKey,
  onPreviewSketchSshKeyRemoval,
  onPreviewSketchSshKeyRotation,
  onRemoveSketchSshKey,
  onRotateSketchSshKey,
  onCreateReplacementSketchChain,
  onDeploySketchChainRecord,
  onCancelSketchChainRecord,
  onMarkSketchChainBurned,
  onUpdateSketchChainRecord,
  onTeardownSketchChainRecord,
  onStartSketchChainRecord,
  onStopSketchChainRecord,
  onUpdateSketchChainPowerConfirmation,
  onRetireSketchChainFinalEdge,
  onReplaceSketchChainFinalEdge,
  corePlan,
  corePlanStatus,
  providerCatalogs,
  providerCatalogStatus,
  providerRegionPolicies,
  providerRegionPolicyCatalogs,
  providerRegionPolicyMessage,
  providerRegionPolicyStatus,
  revisionHistory,
  revisionHistoryStatus,
  revisionRenderResult,
  revisionRenderStatus,
  selectedEngagement,
  selectedEngagementId,
  selectedInfrastructureTemplate,
  selectedInfrastructureTemplateId,
  selectedJobDetail,
  selectedJobDetailStatus,
  selectedRevisionId,
  setGuidedBackflipEnabled,
  setGuidedElkEnabled,
  setGuidedEngagementName,
  setGuidedOperators,
  setGuidedSshEnabled,
  setSelectedInfrastructureTemplateId,
  selectedDeploymentTargetName,
  setSelectedDeploymentTargetName,
  setHousekeepingItemsDraft,
  setInfrastructureConsoleOpen,
  setInboundChannelDraft,
  setOutboundChannelDraft,
  setCredentialForm,
  setDigitalOceanProviderSmokeAction,
  setSketchSshKeyRemovalAction,
  setSketchSshKeyRotationAction,
  setSketchIntent,
  setSketchChainCancelTarget,
  setSketchChainCancelConfirmation,
  setSketchChainTeardownTarget,
  setSketchChainTeardownConfirmation,
  setSketchEdgeTransitionConfirmations,
  setSketchEdgeReplacementRegions,
  setObserverForbiddenPortsInput,
  setObserverCheckAction,
  setActiveEngagementTab,
  setActiveGlobalSettingsTab,
  setTestDeployConfirmation,
  setTestDeploySshSourceCidrs,
  setTestDeployTeardownConfirmation,
  setTestDeployTeardownStatus,
  setSelectedRevisionId,
  setSelectedEngagementId,
  stats,
  dashboard,
  dashboardProviderRefreshStatus,
  dashboardStatus,
  providerOrphanRecoveryAction,
  testDeployConfirmation,
  testDeploySshSourceCidrs,
  testDeployReadiness,
  testDeployReadinessStatus,
  testDeployResult,
  testDeployRunJob,
  teardownParentLoadStatus,
  teardownRequestPending,
  teardownRequestUnconfirmed,
  testDeployRunStatus,
  testDeployTeardownConfirmation,
  testDeployTeardownStatus,
  engagementTeardownPreview,
  engagementTeardownPreviewStatus
}: {
  activeView: ViewKey;
  activeGlobalSettingsTab: GlobalSettingsTabKey;
  activeEngagementTab: EngagementTabKey;
  currentUser?: AuthenticatedUser;
  isAdministrator: boolean;
  credentialForm: CredentialFormState;
  credentialMessage: string;
  credentials: CredentialSummary[];
  credentialsStatus: "idle" | "loading" | "ready" | "saving" | "error";
  digitalOceanPreflightAction: ProviderPreflightActionState;
  digitalOceanProviderSmokeAction: DigitalOceanProviderSmokeActionState;
  data: AppData;
  engagementOperations: EngagementOperationsOverview | null;
  engagementOperationsStatus: "idle" | "loading" | "ready" | "saving" | "error";
  engagementWorkspace: EngagementWorkspaceRecord | null;
  engagementWorkspaceStatus: "idle" | "loading" | "preparing" | "ready" | "error";
  engagementWorkflowRevision: DeploymentRevision | null;
  engagementWorkflowStatus: "idle" | "creating" | "compiling" | "ready" | "error";
  backflipsServiceAction: BackflipsServiceActionState;
  desktopServiceAction: DesktopServiceActionState;
  genericServiceAction: GenericServiceActionState;
  genericServiceForm: GenericServiceFormState;
  webStaticServiceAction: WebStaticServiceActionState;
  webStaticServiceForm: WebStaticServiceFormState;
  webStaticServiceRemovalAction: WebStaticServiceRemovalActionState;
  guidedBackflipEnabled: boolean;
  guidedDeploymentInput: ReturnType<typeof standardRtiPreviewInput>;
  guidedEngagementName: string;
  guidedOperators: string;
  guidedOperatorsList: string[];
  guidedSshEnabled: boolean;
  housekeepingItemsDraft: string;
  infrastructureConsoleOpen: boolean;
  jobsPagination: JobRunPagination;
  jobsStatus: "idle" | "loading" | "ready" | "error";
  inboundChannelAction: InboundChannelActionState;
  inboundChannelDraft: InboundChannelFormState;
  linodeSketchChain: ReturnType<typeof sketchChainsWithIds>[number] | null;
  linodeSketchRunJob: JobRunDetail | null;
  linodeSketchRunStatus: "idle" | "running" | "ready" | "error";
  deployableInitialSketchChains: ReturnType<typeof sketchChainsWithIds>;
  sketchDeploymentJobs: JobRunDetail[];
  outboundChannelAction: OutboundChannelActionState;
  outboundChannelDraft: OutboundChannelFormState;
  sketchSshKey: SketchSshKey | null;
  sketchSshKeyStatus: "idle" | "loading" | "ready" | "saving" | "downloaded" | "error";
  sketchSshKeyRemovalAction: SketchSshKeyRemovalActionState;
  sketchSshKeyRotationAction: SketchSshKeyRotationActionState;
  sketchChainRecords: SketchChainRecord[];
  sketchChainRecordsStatus: "idle" | "loading" | "ready" | "saving" | "error";
  sketchChainMessage: string;
  sketchChainCancelTarget: string | null;
  sketchChainCancelConfirmation: string;
  sketchChainPowerConfirmations: Record<string, string>;
  sketchEdgeTransitionConfirmations: Record<string, string>;
  sketchEdgeReplacementRegions: Record<string, string>;
  sketchChainTeardownTarget: string | null;
  sketchChainTeardownConfirmation: string;
  sketchIntent: SketchIntentState;
  observerSettings: ObserverSettings | null;
  observerForbiddenPortsInput: string;
  observerCheckAction: ObserverCheckActionState;
  onChangePassword?: () => void;
  onSignOut?: () => void;
  onSignOutAll?: () => void;
  onArchiveEngagement: (engagementId: string) => Promise<EngagementDetail>;
  onCompileSelectedRevision: () => void;
  onCreateCredential: () => void;
  onCreateEngagement: (metadata: EngagementMetadataFormState, sketchStateSchema: "split-v1" | "provider-keyed-v2") => Promise<EngagementDetail>;
  onDeleteEngagement: (engagementId: string) => Promise<EngagementDetail>;
  onReconcileEngagement: (engagementId: string) => Promise<EngagementSummary>;
  onDisableCredential: (credentialId: string) => void;
  onRunDigitalOceanSketchPreflight: () => void;
  onRunDigitalOceanProviderSmokeValidation: () => void;
  onEditEngagement: (engagementId: string, metadata: EngagementMetadataFormState) => Promise<EngagementDetail>;
  onRefreshCredentials: () => Promise<CredentialSummary[]>;
  onRefreshProviderRegionPolicies: () => Promise<ProviderRegionPolicy[]>;
  onEnsureProviderCatalogs: () => Promise<Record<string, SketchProviderCatalog>>;
  onUpdateProviderRegionPolicy: (provider: string, regionId: string, allowed: boolean) => void;
  onUpdateObserverSettingsDraft: (patch: Partial<Pick<ObserverSettings, "enabled" | "provider" | "region" | "size" | "mode" | "scheduleWeekdays" | "scheduleTimeUtc" | "checkFamilies" | "portScanProfiles">>) => void;
  onSaveObserverSettings: () => void;
  onEnsureInspectorReadiness: () => void;
  onRunObserverCheck: () => void;
  onInspectorCleanupComplete: () => Promise<ObserverSettings | null>;
  onRefreshLinodeSketchRun: () => void;
  onLoadSelectedRevisions: () => void;
  onLoadJobsPage: (offset: number) => void;
  onOpenEngagementWorkspace: (engagementId: string) => void;
  onPrepareEngagementWorkspace: () => void;
  onRunTestDeployment: (options?: { recreateCore?: boolean; recreateConfirmation?: string }) => void;
  onRecordChannels: () => void;
  onRecoverProviderOrphan: (
    candidate: DashboardOrphanCandidate,
    action: ProviderOrphanRecoveryAction,
    options?: { mutation?: boolean; confirmation?: string }
  ) => void;
  onOpenLifecycleConsole: (source: Exclude<LifecycleConsoleSource, null>) => void;
  onRefreshDashboardProviderInventory: () => void;
  onSetProviderOrphanTeardownConfirmation: (candidateId: string, value: string) => void;
  onCreateInboundChannel: (body: InboundChannelCreateRequest) => void;
  onEditInboundChannel: (channel: EngagementOperationsOverview["inboundChannels"][number]) => void;
  onDisableInboundChannel: (channel: EngagementOperationsOverview["inboundChannels"][number]) => void;
  onRemoveInboundChannel: (channel: EngagementOperationsOverview["inboundChannels"][number]) => void;
  onRecoverInboundChannel: (channel: EngagementOperationsOverview["inboundChannels"][number]) => void;
  onSaveHousekeepingItems: () => void;
  onPreviewInboundChannelApply: (channelId: string) => void;
  onApplyInboundChannel: (channelId: string) => void;
  onValidateInboundChannel: (channelId: string) => void;
  onUpdateInboundChannelConfirmation: (channelId: string, kind: "apply" | "validate" | "remove", value: string) => void;
  onRefreshEngagementOperations: () => Promise<EngagementOperationsOverview | null>;
  onPreviewOutboundChannelApply: (chainId: string) => void;
  onApplyOutboundChannel: (chainId: string) => void;
  onValidateOutboundChannel: (chainId: string) => void;
  onUpdateOutboundChannelConfirmation: (chainId: string, value: string) => void;
  onPreviewBackflipsServiceApply: () => void;
  onApplyBackflipsService: () => void;
  onUpdateBackflipsServiceAction: (patch: Partial<BackflipsServiceActionState>) => void;
  backflipsConsoleOpen: boolean;
  backflipsConsoleCopied: boolean;
  setBackflipsConsoleOpen: (value: boolean) => void;
  setBackflipsConsoleCopied: (value: boolean) => void;
  onApplyDesktopService: (desiredApps?: DesktopServiceDesiredApp[]) => void;
  onPreviewWebStaticServiceApply: () => void;
  onApplyWebStaticService: () => void;
  onRestoreWebStaticService: (request: WebStaticServiceRequest) => void;
  onPreviewWebStaticServiceRemove: (serviceId: string) => void;
  onApplyWebStaticServiceRemove: () => void;
  onUpdateWebStaticServiceForm: (patch: Partial<WebStaticServiceFormState>) => void;
  onResetWebStaticServiceAction: () => void;
  onUpdateWebStaticServiceRemovalAction: (
    value: WebStaticServiceRemovalActionState | ((current: WebStaticServiceRemovalActionState) => WebStaticServiceRemovalActionState)
  ) => void;
  onSaveGenericService: () => void;
  onDisableGenericService: (serviceId: string) => void;
  onRestoreGenericService: (serviceId: string) => void;
  onRemoveGenericService: (serviceId: string) => void;
  onUpdateGenericServiceForm: (patch: Partial<GenericServiceFormState>) => void;
  onUpdateGenericServiceAction: (value: GenericServiceActionState | ((current: GenericServiceActionState) => GenericServiceActionState)) => void;
  onRefreshTestDeploymentRun: () => void;
  onRenderSelectedRevision: () => void;
  onBeginTestDeploymentTeardown: () => void;
  onTeardownTestDeploymentRun: () => void;
  onRotateCredential: (credential: CredentialSummary) => void;
  onResumePilotRunFromJob: (job: JobRunDetail) => void;
  onSelectJob: (jobId: string) => void;
  onSetDefaultCredential: (credentialId: string) => void;
  onValidateCredential: (credentialId: string) => void;
  onGenerateSketchSshKey: () => void;
  onDownloadSketchSshKey: () => void;
  onPreviewSketchSshKeyRemoval: () => void;
  onPreviewSketchSshKeyRotation: () => void;
  onRemoveSketchSshKey: () => void;
  onRotateSketchSshKey: () => void;
  onCreateReplacementSketchChain: (proxy: string) => void;
  onDeploySketchChainRecord: (chain: SketchChainRecord) => void;
  onCancelSketchChainRecord: (chain: SketchChainRecord) => void;
  onMarkSketchChainBurned: (chain: SketchChainRecord) => void;
  onUpdateSketchChainRecord: (chain: SketchChainRecord, patch: UpdateSketchChainRequest) => void;
  onTeardownSketchChainRecord: (chain: SketchChainRecord) => void;
  onStartSketchChainRecord: (chain: SketchChainRecord) => void;
  onStopSketchChainRecord: (chain: SketchChainRecord) => void;
  onUpdateSketchChainPowerConfirmation: (chainId: string, value: string) => void;
  onRetireSketchChainFinalEdge: (chain: SketchChainRecord) => void;
  onReplaceSketchChainFinalEdge: (chain: SketchChainRecord) => void;
  corePlan: CoreInfrastructurePlan | null;
  corePlanStatus: CoreInfrastructurePlanStatus | "loading";
  providerCatalogs: Record<string, SketchProviderCatalog>;
  providerCatalogStatus: "idle" | "loading" | "ready" | "error";
  providerRegionPolicies: Record<string, ProviderRegionPolicy>;
  providerRegionPolicyCatalogs: Record<string, SketchProviderCatalog>;
  providerRegionPolicyMessage: string;
  providerRegionPolicyStatus: "idle" | "loading" | "ready" | "saving" | "error";
  revisionHistory: DeploymentRevision[];
  revisionHistoryStatus: "idle" | "loading" | "ready" | "error";
  revisionRenderResult: RenderResult | null;
  revisionRenderStatus: "idle" | "rendering" | "ready" | "error";
  selectedEngagement: EngagementSummary | null;
  selectedEngagementId: string | null;
  selectedInfrastructureTemplate: TemplateSummary | undefined;
  selectedInfrastructureTemplateId: string;
  selectedJobDetail: JobRunDetail | null;
  selectedJobDetailStatus: "idle" | "loading" | "ready" | "error";
  selectedRevisionId: string | null;
  setGuidedBackflipEnabled: (value: boolean) => void;
  setGuidedElkEnabled: (value: boolean) => void;
  setGuidedEngagementName: (value: string) => void;
  setGuidedOperators: (value: string) => void;
  setGuidedSshEnabled: (value: boolean) => void;
  setSelectedInfrastructureTemplateId: (value: string) => void;
  selectedDeploymentTargetName: string;
  setSelectedDeploymentTargetName: (value: string) => void;
  setHousekeepingItemsDraft: (value: string) => void;
  setInfrastructureConsoleOpen: (value: boolean) => void;
  setInboundChannelDraft: (value: InboundChannelFormState) => void;
  setOutboundChannelDraft: (value: OutboundChannelFormState) => void;
  setCredentialForm: (value: CredentialFormState) => void;
  setDigitalOceanProviderSmokeAction: (value: DigitalOceanProviderSmokeActionState | ((current: DigitalOceanProviderSmokeActionState) => DigitalOceanProviderSmokeActionState)) => void;
  setSketchSshKeyRemovalAction: (value: SketchSshKeyRemovalActionState | ((current: SketchSshKeyRemovalActionState) => SketchSshKeyRemovalActionState)) => void;
  setSketchSshKeyRotationAction: (value: SketchSshKeyRotationActionState | ((current: SketchSshKeyRotationActionState) => SketchSshKeyRotationActionState)) => void;
  setSketchIntent: (value: SketchIntentState) => void;
  setSketchChainCancelTarget: (chainId: string | null) => void;
  setSketchChainCancelConfirmation: (value: string) => void;
  setSketchChainTeardownTarget: (chainId: string | null) => void;
  setSketchChainTeardownConfirmation: (value: string) => void;
  setSketchEdgeTransitionConfirmations: (value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)) => void;
  setSketchEdgeReplacementRegions: (value: Record<string, string> | ((current: Record<string, string>) => Record<string, string>)) => void;
  setObserverForbiddenPortsInput: (value: string) => void;
  setObserverCheckAction: (value: ObserverCheckActionState | ((current: ObserverCheckActionState) => ObserverCheckActionState)) => void;
  setActiveEngagementTab: (value: EngagementTabKey) => void;
  setActiveGlobalSettingsTab: (value: GlobalSettingsTabKey) => void;
  setTestDeployConfirmation: (value: string) => void;
  setTestDeploySshSourceCidrs: (value: string) => void;
  setTestDeployTeardownConfirmation: (value: string) => void;
  setTestDeployTeardownStatus: (value: "idle" | "confirming" | "running") => void;
  setSelectedRevisionId: (revisionId: string) => void;
  setSelectedEngagementId: (engagementId: string | null) => void;
  stats: { label: string; value: number }[];
  dashboard: DashboardInventory | null;
  dashboardProviderRefreshStatus: "idle" | "running" | "ready" | "error";
  dashboardStatus: "loading" | "ready" | "error";
  providerOrphanRecoveryAction: ProviderOrphanRecoveryActionState;
  testDeployConfirmation: string;
  testDeploySshSourceCidrs: string;
  testDeployReadiness: DisposableDeploymentReadiness | null;
  testDeployReadinessStatus: "idle" | "loading" | "ready" | "error";
  testDeployResult: DisposableDeploymentResult | null;
  testDeployRunJob: JobRunDetail | null;
  teardownParentLoadStatus: "idle" | "loading" | "ready" | "error";
  teardownRequestPending: boolean;
  teardownRequestUnconfirmed: boolean;
  testDeployRunStatus: "idle" | "running" | "ready" | "error";
  testDeployTeardownConfirmation: string;
  testDeployTeardownStatus: "idle" | "confirming" | "running";
  engagementTeardownPreview: EngagementTeardownPreview | null;
  engagementTeardownPreviewStatus: "idle" | "loading" | "ready" | "error";
}) {
  const selectedRevision = revisionHistory.find((revision) => revision.id === selectedRevisionId) ?? null;
  const [infrastructureProgressNow, setInfrastructureProgressNow] = useState(() => Date.now());
  const [sshConfigCopied, setSshConfigCopied] = useState(false);
  const [overviewMarkdownCopied, setOverviewMarkdownCopied] = useState(false);
  const [selectedTerraformPath, setSelectedTerraformPath] = useState("");
  const deployStepHeadingRef = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (corePlanStatus === "ready" || corePlanStatus === "succeeded") {
      deployStepHeadingRef.current?.focus();
    }
  }, [corePlanStatus]);
  const [activeChannelTab, setActiveChannelTab] = useState<"outbound" | "inbound">("outbound");
  const [activeSettingsTab, setActiveSettingsTab] = useState<"general" | "inspector">("general");
  const [inboundComposerOpen, setInboundComposerOpen] = useState(false);
  const [inboundBatchRows, setInboundBatchRows] = useState<InboundChannelBatchRow[]>([]);
  const [inboundBatchEditingId, setInboundBatchEditingId] = useState<string | null>(null);
  const [inboundBatchSubmissionId, setInboundBatchSubmissionId] = useState("");
  const [inboundBatchPreview, setInboundBatchPreview] = useState<InboundChannelBatchPreview | null>(null);
  const [inboundBatchStatus, setInboundBatchStatus] = useState<"idle" | "previewing" | "ready" | "saving" | "applying" | "error">("idle");
  const [inboundBatchMessage, setInboundBatchMessage] = useState("");
  const [inboundBatchJob, setInboundBatchJob] = useState<JobRunDetail | null>(null);
  const [inboundBatchConsoleOpen, setInboundBatchConsoleOpen] = useState(false);
  const inboundBatchRequestSequenceRef = useRef(0);
  const [channelConsoleOpen, setChannelConsoleOpen] = useState(false);
  const [desktopConsoleOpen, setDesktopConsoleOpen] = useState(false);
  const [desktopConsoleCopied, setDesktopConsoleCopied] = useState(false);
  const [certificateManagerOpen, setCertificateManagerOpen] = useState(false);
  const [certificateConsoleOpen, setCertificateConsoleOpen] = useState(false);
  const [bindingCertificateId, setBindingCertificateId] = useState("");
  const certificateRequestSequenceRef = useRef(0);
  const [certificateAction, setCertificateAction] = useState<InboundCertificateActionState>({
    activeChannelId: null,
    status: "idle",
    message: "",
    workspace: null,
    bindingWorkspace: null,
    job: null,
    certificateType: "letsencrypt",
    acmeEmail: "",
    acmeEnvironment: "staging",
    productionConfirmation: ""
  });
  const [requestHeaderGateManagerOpen, setRequestHeaderGateManagerOpen] = useState(false);
  const requestHeaderGateRequestSequenceRef = useRef(0);
  const [requestHeaderGateAction, setRequestHeaderGateAction] = useState<InboundRequestHeaderGateActionState>({
    activeChannelId: null,
    channel: null,
    status: "idle",
    message: "",
    workspace: null,
    job: null,
    enabled: false,
    headerName: "Authorization",
    token: "",
    maxRequestBodyMb: "500",
    copyStatus: "idle"
  });
  const desktopConsoleJobId = desktopServiceAction.job?.id ?? "";

  useEffect(() => {
    let cancelled = false;
    inboundBatchRequestSequenceRef.current += 1;
    setInboundBatchRows([]);
    setInboundBatchEditingId(null);
    setInboundBatchSubmissionId("");
    setInboundBatchPreview(null);
    setInboundBatchStatus("idle");
    setInboundBatchMessage("");
    setInboundBatchJob(null);
    setInboundBatchConsoleOpen(false);
    if (!selectedEngagementId) return () => { cancelled = true; };
    void apiClient.latestInboundChannelBatch(selectedEngagementId).then(({ job }) => {
      if (cancelled || !job) return;
      setInboundBatchJob(job);
      setInboundBatchStatus(["queued", "running"].includes(job.status) ? "applying" : job.status === "succeeded" ? "ready" : "error");
      setInboundBatchMessage(["queued", "running"].includes(job.status) ? "An inbound channel batch is still running." : job.status === "succeeded" ? "The latest inbound channel batch completed." : "The latest inbound channel batch needs attention.");
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [selectedEngagementId]);

  useEffect(() => {
    if (!inboundBatchJob?.id || !["queued", "running"].includes(inboundBatchJob.status)) {
      return;
    }
    let cancelled = false;
    const refresh = () => {
      void apiClient.job(inboundBatchJob.id).then(({ job }) => {
        if (cancelled) return;
        setInboundBatchJob(job);
        if (!["queued", "running"].includes(job.status)) {
          setInboundBatchStatus(job.status === "succeeded" ? "ready" : "error");
          setInboundBatchMessage(job.status === "succeeded" ? "All inbound channels were applied." : "The batch needs attention. Completed channels were retained.");
          void onRefreshEngagementOperations();
        }
      }).catch(() => undefined);
    };
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [inboundBatchJob?.id, inboundBatchJob?.status]);

  const closeRequestHeaderGateManager = () => {
    requestHeaderGateRequestSequenceRef.current += 1;
    setRequestHeaderGateManagerOpen(false);
    setRequestHeaderGateAction({
      activeChannelId: null,
      channel: null,
      status: "idle",
      message: "",
      workspace: null,
      job: null,
      enabled: false,
      headerName: "Authorization",
      token: "",
      maxRequestBodyMb: "500",
      copyStatus: "idle"
    });
  };

  useEffect(() => {
    closeRequestHeaderGateManager();
  }, [selectedEngagementId]);

  const refreshRequestHeaderGate = (channelId: string, requestSequence: number, preserveOutcome = false) => {
    if (!selectedEngagementId) {
      return Promise.resolve(null);
    }
    return apiClient.inboundChannelRequestHeaderGate(selectedEngagementId, channelId).then((workspace) => {
      if (requestHeaderGateRequestSequenceRef.current !== requestSequence) {
        return null;
      }
      const pendingJob = workspace.job ?? null;
      const pendingRunning = workspace.pending?.state === "running" && Boolean(pendingJob && certificateJobIsRunning(pendingJob));
      const pendingRetry = workspace.pending?.state === "retry-required" || (workspace.pending?.state === "running" && !pendingRunning);
      setRequestHeaderGateAction((current) => current.activeChannelId === channelId
        ? {
            ...current,
            status: pendingRunning ? "running" : pendingRetry ? "error" : preserveOutcome ? current.status : "ready",
            message: pendingRunning && pendingJob
              ? requestHeaderGateJobProgressMessage(pendingJob)
              : pendingRetry
                ? workspace.pending?.message || "The prior request access job was interrupted. Apply the policy again to retry safely."
              : preserveOutcome
              ? current.message
              : workspace.gate.enabled
                ? "Request header gate is active."
                : workspace.gate.configured
                  ? "Request header gate is disabled; the retained token can be reused."
                  : "Request header gate has not been configured.",
            workspace,
            job: pendingRunning ? pendingJob : null,
            enabled: preserveOutcome ? current.enabled : workspace.gate.enabled,
            headerName: preserveOutcome ? current.headerName : workspace.gate.headerName || "Authorization",
            token: preserveOutcome ? current.token : workspace.gate.token,
            maxRequestBodyMb: preserveOutcome ? current.maxRequestBodyMb : String(workspace.gate.maxRequestBodyMb ?? 500),
            copyStatus: "idle"
          }
        : current);
      return workspace;
    });
  };

  const openRequestHeaderGateManager = (channel: EngagementOperationsOverview["inboundChannels"][number]) => {
    if (!selectedEngagementId) {
      return;
    }
    const requestSequence = ++requestHeaderGateRequestSequenceRef.current;
    setRequestHeaderGateManagerOpen(true);
    setRequestHeaderGateAction({
      activeChannelId: channel.channelId,
      channel,
      status: "loading",
      message: "Loading request access policy.",
      workspace: null,
      job: null,
      enabled: false,
      headerName: "Authorization",
      token: "",
      maxRequestBodyMb: "500",
      copyStatus: "idle"
    });
    void refreshRequestHeaderGate(channel.channelId, requestSequence).catch((error) => {
      if (requestHeaderGateRequestSequenceRef.current !== requestSequence) {
        return;
      }
      setRequestHeaderGateAction((current) => current.activeChannelId === channel.channelId
        ? { ...current, status: "error", message: barraganApiErrorSummary(error, "Could not load request access policy.") }
        : current);
    });
  };

  const applyRequestHeaderGate = () => {
    const channelId = requestHeaderGateAction.activeChannelId;
    if (!selectedEngagementId || !channelId || !requestHeaderGateFormReady(requestHeaderGateAction)) {
      return;
    }
    const requestSequence = requestHeaderGateRequestSequenceRef.current;
    const body = requestHeaderGateAction.enabled
      ? {
          enabled: true,
          headerName: requestHeaderGateAction.headerName.trim(),
          tokenAction: "provide" as const,
          token: requestHeaderGateAction.token,
          maxRequestBodyMb: Number(requestHeaderGateAction.maxRequestBodyMb)
        }
      : {
          enabled: false,
          headerName: requestHeaderGateAction.workspace?.gate.headerName || "Authorization",
          tokenAction: "keep" as const,
          maxRequestBodyMb: Number(requestHeaderGateAction.maxRequestBodyMb)
        };
    setRequestHeaderGateAction((current) => ({
      ...current,
      status: "running",
      message: "Saving inbound channel policy.",
      job: null,
      copyStatus: "idle"
    }));
    void apiClient.updateInboundChannelRequestHeaderGate(selectedEngagementId, channelId, body).then((workspace) => {
      if (requestHeaderGateRequestSequenceRef.current !== requestSequence) {
        return;
      }
      const job = workspace.job ?? null;
      const running = job ? certificateJobIsRunning(job) : false;
      setRequestHeaderGateAction((current) => current.activeChannelId === channelId
        ? {
            ...current,
            status: running ? "running" : job && job.status !== "succeeded" ? "error" : "ready",
            message: running
              ? requestHeaderGateJobProgressMessage(job)
              : job && job.status !== "succeeded"
                ? requestHeaderGateJobProgressMessage(job)
                : "Request access policy applied.",
            workspace: running ? current.workspace : workspace,
            job
          }
        : current);
      if (!running) {
        void refreshRequestHeaderGate(channelId, requestSequence, Boolean(job && job.status !== "succeeded"));
        void onRefreshEngagementOperations();
      }
    }).catch((error) => {
      if (requestHeaderGateRequestSequenceRef.current !== requestSequence) {
        return;
      }
      setRequestHeaderGateAction((current) => current.activeChannelId === channelId
        ? { ...current, status: "error", message: barraganApiErrorSummary(error, "Could not apply request access policy.") }
        : current);
    });
  };

  const copyRequestHeaderGateValue = (value: string, kind: "token" | "curl") => {
    if (!value || !navigator.clipboard) {
      setRequestHeaderGateAction((current) => ({ ...current, copyStatus: "error" }));
      return;
    }
    void navigator.clipboard.writeText(value).then(
      () => setRequestHeaderGateAction((current) => ({ ...current, copyStatus: kind })),
      () => setRequestHeaderGateAction((current) => ({ ...current, copyStatus: "error" }))
    );
  };

  const generateRequestHeaderGateToken = () => {
    const token = generateRequestGateToken();
    setRequestHeaderGateAction((current) => ({
      ...current,
      token,
      copyStatus: "idle",
      message: "Generated a new token locally. Save the request gate to apply it."
    }));
  };

  useEffect(() => {
    const job = requestHeaderGateAction.job;
    const channelId = requestHeaderGateAction.activeChannelId;
    if (requestHeaderGateAction.status !== "running" || !job || !channelId || !certificateJobIsRunning(job)) {
      return;
    }
    const requestSequence = requestHeaderGateRequestSequenceRef.current;
    let cancelled = false;
    const refresh = () => {
      apiClient.job(job.id).then((response) => {
        if (cancelled || requestHeaderGateRequestSequenceRef.current !== requestSequence || response.job.id !== job.id) {
          return;
        }
        const running = certificateJobIsRunning(response.job);
        setRequestHeaderGateAction((current) => current.activeChannelId === channelId && current.job?.id === response.job.id
          ? {
              ...current,
              status: running ? "running" : response.job.status === "succeeded" ? "ready" : "error",
              message: requestHeaderGateJobProgressMessage(response.job),
              job: response.job
            }
          : current);
        if (!running) {
          void refreshRequestHeaderGate(channelId, requestSequence, response.job.status !== "succeeded");
          void onRefreshEngagementOperations();
        }
      }).catch(() => {
        if (!cancelled && requestHeaderGateRequestSequenceRef.current === requestSequence) {
          setRequestHeaderGateAction((current) => current.activeChannelId === channelId
            ? { ...current, message: "Request access job is still running; waiting for the next update." }
            : current);
        }
      });
    };
    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [requestHeaderGateAction.activeChannelId, requestHeaderGateAction.job?.id, requestHeaderGateAction.job?.status, requestHeaderGateAction.status]);

  useEffect(() => {
    if (activeView !== "workspace" || activeEngagementTab !== "settings" || activeSettingsTab !== "inspector") {
      return;
    }
    void onEnsureProviderCatalogs().catch(() => undefined);
  }, [activeEngagementTab, activeSettingsTab, activeView, onEnsureProviderCatalogs]);

  useEffect(() => {
    if (!testDeployRunJob || !["queued", "running"].includes(testDeployRunJob.status)) {
      return;
    }
    setInfrastructureProgressNow(Date.now());
    const interval = window.setInterval(() => setInfrastructureProgressNow(Date.now()), 1000);
    return () => window.clearInterval(interval);
  }, [testDeployRunJob?.id, testDeployRunJob?.status]);

  useEffect(() => {
    const isDesktopApplyJob = desktopServiceAction.job?.action === "desktop_service_apply";
    const isApplyingDesktopChanges = desktopServiceAction.status === "running" && desktopServiceAction.message.startsWith("Applying Desktop app changes");
    if (isApplyingDesktopChanges || isDesktopApplyJob) {
      setDesktopConsoleOpen(true);
    }
  }, [desktopConsoleJobId, desktopServiceAction.job?.action, desktopServiceAction.message, desktopServiceAction.status]);
  const [activeServiceComposer, setActiveServiceComposer] = useState<ServiceComposerKey | null>(null);
  const [webStaticSiteComposerOpen, setWebStaticSiteComposerOpen] = useState(false);
  const [genericServiceEditorOpen, setGenericServiceEditorOpen] = useState(false);
  const [activeWebStaticServiceId, setActiveWebStaticServiceId] = useState<string | null>(null);
  const [inboundRemoveTarget, setInboundRemoveTarget] = useState<EngagementOperationsOverview["inboundChannels"][number] | null>(null);
  const [coreRecreateConfirmation, setCoreRecreateConfirmation] = useState("");
  useEffect(() => {
    setCoreRecreateConfirmation("");
  }, [selectedEngagementId]);
  useEffect(() => {
    if (
      activeServiceComposer === "web-static" &&
      webStaticSiteComposerOpen &&
      webStaticServiceAction.status === "ready" &&
      webStaticServiceAction.result
    ) {
      setWebStaticSiteComposerOpen(false);
    }
  }, [activeServiceComposer, webStaticServiceAction.result, webStaticServiceAction.status, webStaticSiteComposerOpen]);

  useEffect(() => {
    if (activeServiceComposer === "generic" && genericServiceEditorOpen && genericServiceAction.status === "ready") {
      setGenericServiceEditorOpen(false);
    }
  }, [activeServiceComposer, genericServiceAction.status, genericServiceEditorOpen]);

  const openCertificateManager = (channel: EngagementOperationsOverview["inboundChannels"][number]) => {
    if (!selectedEngagementId) {
      return;
    }
    const requestSequence = ++certificateRequestSequenceRef.current;
    setCertificateManagerOpen(true);
    setCertificateConsoleOpen(false);
    setCertificateAction((current) => ({
      ...current,
      activeChannelId: channel.channelId,
      status: "loading",
      message: "Loading SSL/TLS certificate state.",
      workspace: null,
      bindingWorkspace: null,
      job: null,
      certificateType: (channel.certificate?.type === "self-signed" ? "self-signed" : "letsencrypt"),
      acmeEmail: channel.certificate?.acmeEmail || current.acmeEmail,
      acmeEnvironment: (channel.certificate?.acmeEnvironment === "production" ? "production" : "staging"),
      productionConfirmation: ""
    }));
    apiClient
      .inboundChannelCertificateBinding(selectedEngagementId, channel.channelId)
      .then((workspace) => {
        if (certificateRequestSequenceRef.current !== requestSequence) {
          return;
        }
        setCertificateAction((current) => current.activeChannelId === channel.channelId
          ? {
              ...current,
              status: "ready",
              message: workspace.certificate ? `TLS ${workspace.tlsStatus}.` : "TLS is unbound. Select a covering certificate on this proxy.",
              bindingWorkspace: workspace
            }
          : current);
        setBindingCertificateId(workspace.certificate?.id || "");
      })
      .catch((error) => {
        if (certificateRequestSequenceRef.current !== requestSequence) {
          return;
        }
        setCertificateAction((current) => current.activeChannelId === channel.channelId
          ? {
              ...current,
              status: "error",
              message: barraganApiErrorSummary(error, "Could not load certificate state.")
            }
          : current);
      });
  };

  const saveCertificateBinding = () => {
    if (!selectedEngagementId || !certificateAction.activeChannelId || !bindingCertificateId) return;
    const channelId = certificateAction.activeChannelId;
    setCertificateConsoleOpen(true);
    setCertificateAction((current) => ({ ...current, status: "running", message: "Applying certificate binding.", job: null }));
    void apiClient.bindInboundChannelCertificate(selectedEngagementId, certificateAction.activeChannelId, bindingCertificateId).then((workspace) => {
      const job = workspace.job ?? null;
      const running = job ? certificateJobIsRunning(job) : false;
      setCertificateAction((current) => ({
        ...current,
        status: running ? "running" : "ready",
        message: job ? certificateJobProgressMessage(job) : `TLS ${workspace.tlsStatus}.`,
        bindingWorkspace: workspace,
        job
      }));
      if (!running) {
        void onRefreshEngagementOperations();
        void refreshCertificateBindingWorkspace(channelId);
      }
    }).catch((error) => setCertificateAction((current) => ({ ...current, status: "error", message: barraganApiErrorSummary(error, "Could not bind certificate.") })));
  };

  const removeCertificateBinding = () => {
    if (!selectedEngagementId || !certificateAction.activeChannelId) return;
    const channelId = certificateAction.activeChannelId;
    setCertificateConsoleOpen(true);
    setCertificateAction((current) => ({ ...current, status: "running", message: "Removing certificate binding.", job: null }));
    void apiClient.unbindInboundChannelCertificate(selectedEngagementId, certificateAction.activeChannelId).then((workspace) => {
      const job = workspace.job ?? null;
      const running = job ? certificateJobIsRunning(job) : false;
      if (!workspace.binding) {
        setBindingCertificateId("");
      }
      setCertificateAction((current) => ({
        ...current,
        status: running ? "running" : "ready",
        message: job ? certificateJobProgressMessage(job) : "TLS certificate unbound; the HTTPS route remains configured.",
        bindingWorkspace: workspace,
        job
      }));
      if (!running) {
        void onRefreshEngagementOperations();
        void refreshCertificateBindingWorkspace(channelId);
      }
    }).catch((error) => setCertificateAction((current) => ({ ...current, status: "error", message: barraganApiErrorSummary(error, "Could not unbind certificate.") })));
  };

  const refreshCertificateBindingWorkspace = (channelId: string) => {
    if (!selectedEngagementId) {
      return Promise.resolve(null);
    }
    const requestSequence = certificateRequestSequenceRef.current;
    return apiClient.inboundChannelCertificateBinding(selectedEngagementId, channelId).then((workspace) => {
      if (certificateRequestSequenceRef.current !== requestSequence) {
        return null;
      }
      setBindingCertificateId(workspace.certificate?.id || "");
      setCertificateAction((current) => current.activeChannelId === channelId
        ? {
            ...current,
            bindingWorkspace: workspace,
            message: workspace.certificate ? `TLS ${workspace.tlsStatus}.` : "TLS certificate unbound; the HTTPS route remains configured."
          }
        : current);
      return workspace;
    }).catch(() => null);
  };

  const refreshCertificateManager = (channelId: string) => {
    if (!selectedEngagementId) {
      return Promise.resolve(null);
    }
    const requestSequence = certificateRequestSequenceRef.current;
    return apiClient
      .inboundChannelCertificate(selectedEngagementId, channelId)
      .then((workspace) => {
        if (certificateRequestSequenceRef.current !== requestSequence) {
          return null;
        }
        setCertificateAction((current) => current.activeChannelId === channelId
          ? {
              ...current,
              workspace,
              status: current.status === "error" ? "ready" : current.status,
              message: current.message || workspace.prerequisites.summary
            }
          : current);
        return workspace;
      })
      .catch(() => null);
  };

  const issueOrRenewCertificate = (action: "issue" | "renew") => {
    if (!selectedEngagementId || !certificateAction.activeChannelId) {
      return;
    }
    const channelId = certificateAction.activeChannelId;
    const requestSequence = ++certificateRequestSequenceRef.current;
    const body: InboundChannelCertificateRequest = {
      certificateType: certificateAction.certificateType,
      acmeEnvironment: certificateAction.acmeEnvironment,
      ...(certificateAction.certificateType === "letsencrypt" ? { acmeEmail: certificateAction.acmeEmail } : {}),
      ...(certificateAction.certificateType === "letsencrypt" && certificateAction.acmeEnvironment === "production"
        ? { productionConfirmation: certificateAction.productionConfirmation }
        : {}),
      requestedBy: "operator"
    };
    setCertificateConsoleOpen(true);
    setCertificateAction((current) => ({
      ...current,
      status: "running",
      message: action === "renew" ? "Renewing SSL/TLS certificate." : "Issuing SSL/TLS certificate.",
      job: null
    }));
    const request = action === "renew"
      ? apiClient.renewInboundChannelCertificate(selectedEngagementId, channelId, body)
      : apiClient.issueInboundChannelCertificate(selectedEngagementId, channelId, body);
    request
      .then((response) => handleCertificateActionResponse(channelId, response, action === "renew" ? "Certificate renewal completed." : "Certificate issue completed.", requestSequence))
      .catch((error) => {
        if (certificateRequestSequenceRef.current !== requestSequence) {
          return;
        }
        setCertificateAction((current) => current.activeChannelId === channelId
          ? {
              ...current,
              status: "error",
              message: barraganApiErrorSummary(error, action === "renew" ? "Could not renew certificate." : "Could not issue certificate.")
            }
          : current);
      });
  };

  const revokeCertificate = () => {
    if (!selectedEngagementId || !certificateAction.activeChannelId) {
      return;
    }
    const channelId = certificateAction.activeChannelId;
    const requestSequence = ++certificateRequestSequenceRef.current;
    setCertificateConsoleOpen(true);
    setCertificateAction((current) => ({ ...current, status: "running", message: "Revoking SSL/TLS certificate.", job: null }));
    apiClient
      .revokeInboundChannelCertificate(selectedEngagementId, channelId)
      .then((response) => handleCertificateActionResponse(channelId, response, "Certificate revoked.", requestSequence))
      .catch((error) => {
        if (certificateRequestSequenceRef.current !== requestSequence) {
          return;
        }
        setCertificateAction((current) => current.activeChannelId === channelId
          ? { ...current, status: "error", message: barraganApiErrorSummary(error, "Could not revoke certificate.") }
          : current);
      });
  };

  const handleCertificateActionResponse = (channelId: string, response: InboundChannelCertificateActionResult, message: string, requestSequence: number) => {
    if (certificateRequestSequenceRef.current !== requestSequence) {
      return;
    }
    const running = certificateJobIsRunning(response.job);
    const succeeded = response.job.status === "succeeded";
    setCertificateAction((current) => current.activeChannelId === channelId
      ? {
          ...current,
          status: running ? "running" : succeeded ? "ready" : "error",
          message: running ? certificateJobProgressMessage(response.job) : succeeded ? message : certificateJobProgressMessage(response.job),
          job: response.job,
          workspace: response.certificate && current.workspace
            ? { ...current.workspace, certificate: response.certificate, prerequisites: response.prerequisites ?? current.workspace.prerequisites }
            : current.workspace
        }
      : current);
    if (!running) {
      void onRefreshEngagementOperations();
      void refreshCertificateManager(channelId);
    }
  };

  useEffect(() => {
    const job = certificateAction.job;
    const channelId = certificateAction.activeChannelId;
    if (!job || !channelId || !certificateJobIsRunning(job)) {
      return;
    }
    const requestSequence = certificateRequestSequenceRef.current;
    let cancelled = false;
    const refresh = () => {
      apiClient
        .job(job.id)
        .then((response) => {
          if (cancelled || certificateRequestSequenceRef.current !== requestSequence || response.job.id !== job.id) {
            return;
          }
          const running = certificateJobIsRunning(response.job);
          setCertificateAction((current) =>
            current.activeChannelId === channelId && current.job?.id === response.job.id
              ? {
                  ...current,
                  status: running ? "running" : response.job.status === "succeeded" ? "ready" : "error",
                  message: certificateJobProgressMessage(response.job),
                  job: response.job
                }
              : current
          );
          if (!running && certificateRequestSequenceRef.current === requestSequence) {
            void onRefreshEngagementOperations();
            void refreshCertificateManager(channelId);
            void refreshCertificateBindingWorkspace(channelId);
          }
        })
        .catch(() => {
          if (!cancelled && certificateRequestSequenceRef.current === requestSequence) {
            setCertificateAction((current) =>
              current.activeChannelId === channelId && current.job?.id === job.id
                ? { ...current, status: "running", message: "Certificate job is still running; waiting for the next progress update." }
                : current
            );
          }
        });
    };
    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [certificateAction.activeChannelId, certificateAction.job?.id, certificateAction.job?.status]);

  const updateSketchChain = (chainIndex: number, patch: Partial<SketchIntentState[number]>) => {
    setSketchIntent(sketchIntent.map((chain, index) => (index === chainIndex ? { ...chain, ...patch } : chain)));
  };

  const addSketchChain = (assignedProxy: string) => {
    setSketchIntent([...sketchIntent, defaultSketchChain(assignedProxy)]);
  };

  const removeSketchChain = (chainIndex: number) => {
    if (sketchIntent.length <= 1) {
      return;
    }
    setSketchIntent(sketchIntent.filter((_chain, index) => index !== chainIndex));
  };
  const updateInboundChannel = (patch: Partial<InboundChannelFormState>) => {
    setInboundBatchPreview(null);
    setInboundBatchStatus("idle");
    const next = { ...inboundChannelDraft, ...patch };
    if (patch.protocol || patch.mode) {
      if (patch.protocol === "UDP" || patch.mode === "udp-forward") {
        next.protocol = "UDP";
        next.mode = "udp-forward";
        if (!patch.service) {
          next.service = "";
          next.serviceId = "";
          next.serviceType = "";
        }
        if (!patch.validationProfile) {
          next.validationProfile = { ...defaultUdpInboundValidationProfile };
        }
      } else if (patch.mode === "http-openresty" || patch.protocol === "HTTP") {
        next.protocol = "HTTP";
        next.mode = "http-openresty";
        next.externalPort = "80";
        if (!patch.validationProfile) {
          next.validationProfile = { ...defaultHttpInboundValidationProfile };
        }
      } else if (inboundDraftUsesUdp(inboundChannelDraft)) {
        next.mode = patch.mode ?? (next.protocol === "HTTPS" ? "https-openresty" : "tcp-forward");
        next.relayPort = "";
        next.middleRelayPort = "";
        next.proxyRelayPort = "";
        if (!patch.validationProfile) {
          next.validationProfile = { ...defaultInboundValidationProfile };
        }
      }
    }
    if (patch.service === "" && !patch.validationProfile) {
      next.validationProfile = defaultValidationProfileForInboundDraft(next);
    }
    setInboundChannelDraft(next);
  };
  const updateInboundValidationProfile = (patch: Partial<InboundValidationProfile>) => {
    setInboundBatchPreview(null);
    setInboundBatchStatus("idle");
    const nextType = patch.type ?? inboundChannelDraft.validationProfile.type;
    const option = inboundValidationProfileOptions.find((candidate) => candidate.type === nextType);
    const base = patch.type
      ? { type: nextType, label: option?.label ?? nextType }
      : { ...inboundChannelDraft.validationProfile, type: nextType, label: option?.label ?? inboundChannelDraft.validationProfile.label ?? nextType };
    setInboundChannelDraft({
      ...inboundChannelDraft,
      validationProfile: {
        ...base,
        ...patch
      }
    });
  };
  const updateOutboundChannel = (patch: Partial<OutboundChannelFormState>) => {
    setOutboundChannelDraft({ ...outboundChannelDraft, ...patch });
  };
  const inboundEngagementName = selectedEngagement?.name ?? "";
  const inboundHostOptions = inboundHostOptionsFromOperations(engagementOperations, inboundChannelDraft, inboundEngagementName);
  const inboundAttachment = inboundEdgeAttachment(
    engagementOperations,
    inboundChannelDraft.chainId,
    inboundChannelDraft.edgeComponentId,
    inboundChannelDraft.edge,
    inboundEngagementName
  );
  const inboundTerminationOptions = inboundAttachment
    ? [
        { value: inboundAttachment.proxyHostname, label: inboundAttachment.proxyLabel },
        { value: inboundAttachment.homebaseHostname, label: "homebase" }
      ]
    : [];
  const inboundBackflipsWarning = inboundBackflipsProxySocketWarning(inboundChannelDraft, inboundAttachment);
  const inboundDraftUsesSharedWeb = ["http-openresty", "https-openresty"].includes(inboundChannelDraft.mode);
  const inboundCreateReady = Boolean(
    inboundAttachment &&
      inboundChannelDraft.chainId.trim() &&
      inboundChannelDraft.edgeComponentId.trim() &&
      inboundChannelDraft.edge.trim() &&
      inboundChannelDraft.externalPort.trim() &&
      inboundChannelDraft.terminatesOn.trim() &&
      inboundChannelDraft.internalPort.trim() &&
      (!inboundDraftUsesSharedWeb || inboundChannelDraft.domain.trim()) &&
      !inboundBackflipsWarning
  );
  const inboundRequestFromDraft = (): InboundChannelCreateRequest => ({
    chainId: inboundChannelDraft.chainId,
    edge: inboundChannelDraft.edge,
    edgeComponentId: inboundChannelDraft.edgeComponentId,
    protocol: inboundChannelDraft.protocol,
    mode: inboundChannelDraft.mode,
    externalPort: inboundChannelDraft.externalPort,
    terminatesOn: inboundChannelDraft.terminatesOn,
    internalPort: inboundChannelDraft.internalPort,
    ...(inboundChannelDraft.service ? { service: inboundChannelDraft.service } : {}),
    ...(inboundChannelDraft.serviceId ? { serviceId: inboundChannelDraft.serviceId } : {}),
    ...(inboundChannelDraft.serviceType ? { serviceType: inboundChannelDraft.serviceType } : {}),
    domain: inboundChannelDraft.domain,
    purpose: inboundChannelDraft.purpose,
    ...(inboundChannelDraft.validationProfile.type !== defaultInboundValidationProfile.type ||
    inboundChannelDraft.validationProfile.requestText ||
    inboundChannelDraft.validationProfile.expectedResponse
      ? { validationProfile: inboundChannelDraft.validationProfile }
      : {})
  });
  const invalidateInboundBatchPreview = () => {
    setInboundBatchPreview(null);
    setInboundBatchStatus("idle");
    setInboundBatchMessage("");
  };
  const closeInboundBatchComposer = () => {
    inboundBatchRequestSequenceRef.current += 1;
    setInboundComposerOpen(false);
  };
  const addCurrentInboundBatchRow = () => {
    if (!inboundCreateReady || inboundBatchRows.length >= 20) return;
    const body = inboundRequestFromDraft();
    setInboundBatchRows((current) => inboundBatchEditingId
      ? current.map((row) => row.localId === inboundBatchEditingId ? { ...row, body } : row)
      : [...current, { localId: crypto.randomUUID(), body }]);
    setInboundBatchEditingId(null);
    setInboundChannelDraft({ ...emptyInboundChannelForm });
    invalidateInboundBatchPreview();
  };
  const previewCurrentInboundBatch = () => {
    if (!selectedEngagementId || inboundBatchStatus === "previewing") return;
    const engagementId = selectedEngagementId;
    const requestSequence = ++inboundBatchRequestSequenceRef.current;
    let rows = [...inboundBatchRows];
    if (inboundBatchEditingId && inboundCreateReady) {
      const body = inboundRequestFromDraft();
      rows = rows.map((row) => row.localId === inboundBatchEditingId ? { ...row, body } : row);
      setInboundBatchEditingId(null);
      setInboundChannelDraft({ ...emptyInboundChannelForm });
    } else if (inboundCreateReady) {
      rows = [...rows, { localId: crypto.randomUUID(), body: inboundRequestFromDraft() }];
      setInboundChannelDraft({ ...emptyInboundChannelForm });
    }
    if (!rows.length) return;
    const submissionId = crypto.randomUUID();
    setInboundBatchRows(rows);
    setInboundBatchSubmissionId(submissionId);
    setInboundBatchStatus("previewing");
    setInboundBatchMessage("Checking every channel before any changes are made.");
    apiClient.previewInboundChannelBatch(engagementId, submissionId, rows.map((row) => row.body))
      .then((preview) => {
        if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
        setInboundBatchPreview(preview);
        setInboundBatchStatus("ready");
        setInboundBatchMessage("");
      })
      .catch((error) => {
        if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
        setInboundBatchStatus("error");
        setInboundBatchMessage(barraganApiErrorSummary(error, "Could not review the inbound channel batch."));
      });
  };
  const applyCurrentInboundBatch = () => {
    if (!selectedEngagementId || !inboundBatchPreview || inboundBatchStatus === "applying") return;
    const engagementId = selectedEngagementId;
    const requestSequence = ++inboundBatchRequestSequenceRef.current;
    setInboundBatchStatus("applying");
    setInboundBatchMessage("Applying channels in the reviewed order.");
    apiClient.createInboundChannelBatch(
      engagementId,
      inboundBatchSubmissionId,
      inboundBatchPreview.previewFingerprint,
      inboundBatchRows.map((row) => row.body)
    ).then((result) => {
      if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
      setInboundBatchJob(result.job);
      setInboundBatchMessage("Batch apply started. Completed channels are retained if a later row fails.");
      setInboundComposerOpen(false);
      setInboundBatchConsoleOpen(true);
      void onRefreshEngagementOperations();
    }).catch((error) => {
      if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
      setInboundBatchStatus("error");
      setInboundBatchMessage(barraganApiErrorSummary(error, "Could not apply the reviewed inbound channel batch."));
    });
  };
  const saveCurrentInboundPending = () => {
    if (!selectedEngagementId || !inboundBatchPreview || inboundBatchRows.length !== 1 || inboundBatchStatus === "saving") return;
    const engagementId = selectedEngagementId;
    const requestSequence = ++inboundBatchRequestSequenceRef.current;
    setInboundBatchStatus("saving");
    setInboundBatchMessage("Saving the reviewed route without running infrastructure changes.");
    apiClient.prepareInboundChannel(
      engagementId,
      inboundBatchSubmissionId,
      inboundBatchPreview.previewFingerprint,
      inboundBatchRows[0].body
    ).then(() => {
      if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
      setInboundBatchRows([]);
      setInboundBatchPreview(null);
      setInboundBatchStatus("idle");
      setInboundBatchMessage("Saved Pending. No infrastructure changes have run.");
      void onRefreshEngagementOperations();
    }).catch((error) => {
      if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
      setInboundBatchStatus("error");
      setInboundBatchMessage(barraganApiErrorSummary(error, "Could not save the reviewed inbound channel."));
    });
  };
  const retryCurrentInboundBatch = () => {
    if (!selectedEngagementId || !inboundBatchJob || ["queued", "running"].includes(inboundBatchJob.status)) return;
    const engagementId = selectedEngagementId;
    const requestSequence = ++inboundBatchRequestSequenceRef.current;
    setInboundBatchStatus("applying");
    setInboundBatchMessage("Retrying only failed or not-started channels.");
    apiClient.retryInboundChannelBatch(engagementId, inboundBatchJob.id).then((result) => {
      if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
      setInboundBatchJob(result.job);
      setInboundBatchConsoleOpen(true);
    }).catch((error) => {
      if (requestSequence !== inboundBatchRequestSequenceRef.current) return;
      setInboundBatchStatus("error");
      setInboundBatchMessage(barraganApiErrorSummary(error, "Could not retry the inbound channel batch."));
    });
  };
  const closeInboundBatchConsole = () => {
    inboundBatchRequestSequenceRef.current += 1;
    setInboundBatchConsoleOpen(false);
  };
  const requestGateIsManagedGoSUS = requestHeaderGateAction.workspace?.backendPolicy?.capabilityId === "go-simple-upload-server";

  if (activeView === "engagements") {
    return (
      <EngagementManagementPage
        engagements={data.engagements}
        onArchive={onArchiveEngagement}
        onCreate={onCreateEngagement}
        onDelete={onDeleteEngagement}
        onReconcile={onReconcileEngagement}
        onEdit={onEditEngagement}
        onOpenWorkspace={onOpenEngagementWorkspace}
      />
    );
  }

  if (activeView === "team") {
    return <GlobalTeamPage />;
  }

  if (activeView === "domains") {
    return <DomainInventoryPage engagements={data.engagements} />;
  }

  if (activeView === "templates") {
    return (
      <section className="grid">
        {data.templates.map((template) => (
          <article className="card" key={template.id}>
            <div className="card-header">
              <h3>{template.name}</h3>
              <span>{template.version}</span>
            </div>
            <p>{template.description}</p>
            <div className="pill-row">
              {template.defaultNodeGroups.map((group) => (
                <span className="pill" key={group}>{group}</span>
              ))}
            </div>
          </article>
        ))}
      </section>
    );
  }

  if (activeView === "workspace") {
    const activeInfrastructureProxyOptions = proxyOptionsForTemplate(selectedInfrastructureTemplateId);
    const selectedDeploymentTarget =
      testDeployReadiness?.availableTargets?.find((target) => target.name === selectedDeploymentTargetName) ??
      testDeployReadiness?.target ??
      null;
    const sshSourceCidrs = cidrsFromText(testDeploySshSourceCidrs);
    const sshSourceCidrsValid = sshSourceCidrs.length > 0 && !sshSourceCidrs.includes("0.0.0.0/0");
    const reviewedConfiguration = corePlan?.reviewedConfiguration?.core && corePlan.reviewedConfiguration.target
      ? corePlan.reviewedConfiguration
      : null;
    const reviewedComputeProfile = corePlan?.computeProfile ?? corePlan?.reviewedConfiguration?.computeProfile ?? null;
    const reviewedSketchAuthorization = reviewedConfiguration?.sketchAuthorization ?? null;
    const mixedSketchAwaitingPublication = mixedSketchPublicationPending(corePlan, engagementOperations, selectedEngagement);
    const legacySketchActionsAvailable = (selectedEngagement?.sketchStateSchema ?? "split-v1") === "split-v1";
    const reviewedPostCoreScope = Array.isArray(corePlan?.postCoreScope?.chains) ? corePlan.postCoreScope : null;
    const displayedPostCoreChains = reviewedPostCoreScope?.chains ?? deployableInitialSketchChains.map((chain) => ({
      id: chain.id,
      assignedProxy: chain.assignedProxy,
      middle: { provider: chain.middleProvider, region: chain.middleRegion },
      edges: chain.edges.map((edge) => ({ id: edge.id, provider: edge.provider, region: edge.region }))
    }));
    const corePlanChangeTotal = corePlan
      ? corePlan.counts.add + corePlan.counts.update + corePlan.counts.replace + corePlan.counts.remove + (corePlan.counts.output ?? 0)
      : 0;
    const corePlanHasDestructiveChanges = Boolean(corePlan && (corePlan.counts.replace > 0 || corePlan.counts.remove > 0));
    const corePlanReady = corePlan?.status === "ready" || corePlan?.status === "succeeded";
    const engagementSketchStateSchema = selectedEngagement?.sketchStateSchema ?? "split-v1";
    const planSketchStateSchema = corePlan?.postCoreScope?.sketchStateSchema ?? "split-v1";
    const sketchStateSchemaMismatch = Boolean(corePlan && engagementSketchStateSchema !== planSketchStateSchema);
    const keyedDeploymentUnavailable = selectedEngagement?.sketchStateSchema === "provider-keyed-v2" && corePlan?.keyedDeployEligible !== true;
    const corePlanDeployable = corePlanReady && corePlanChangeTotal > 0 && !corePlanHasDestructiveChanges && !keyedDeploymentUnavailable && !sketchStateSchemaMismatch;
    const coreApplyStepState = corePlan?.status === "applied"
      ? "done"
      : corePlan?.status === "applying" || (corePlanReady && testDeployRunStatus === "running" && !testDeployRunJob)
        ? "wip"
        : corePlanReady && testDeployRunStatus === "error" && !testDeployRunJob
          ? "failed"
          : "pending";
    const corePlanAgeWarningAt = corePlan?.ageWarningAt
      ? Date.parse(corePlan.ageWarningAt)
      : corePlan?.preparedAt
        ? Date.parse(corePlan.preparedAt) + 60 * 60 * 1000
        : Number.POSITIVE_INFINITY;
    const corePlanIsOld = corePlanReady && Date.now() >= corePlanAgeWarningAt;
    const groupedCoreChanges = corePlan?.resourceChanges.reduce<Record<string, CoreInfrastructurePlan["resourceChanges"]>>((groups, change) => {
      (groups[change.group] ??= []).push(change);
      return groups;
    }, {}) ?? {};
    const guidedRunEnabled =
      Boolean(selectedEngagementId) &&
      Boolean(testDeployReadiness) &&
      corePlanDeployable &&
      testDeployConfirmation === testDeployReadiness?.confirmationToken &&
      testDeployRunStatus !== "running";
    const deployGuardrailMessage = testDeployReadiness
      ? guidedRunEnabled
        ? `Deploy is ready to run in ${testDeployReadiness.target.name}.`
        : [
            corePlan?.status === "outdated" || corePlan?.status === "invalidated" ? "prepare a new plan for the edited configuration" : null,
            corePlanReady ? null : "wait for the current core plan",
            corePlanChangeTotal > 0 ? null : "the core plan has no changes",
            corePlanHasDestructiveChanges ? "replacement or removal is blocked for new infrastructure" : null,
            sketchStateSchemaMismatch ? "the saved plan's Sketch state mode differs from the engagement; prepare a new plan" : null,
            keyedDeploymentUnavailable ? "this reviewed DevTest diagnostic is not eligible for deployment" : null,
            testDeployConfirmation === testDeployReadiness.confirmationToken ? null : `enter confirmation token ${testDeployReadiness.confirmationToken}`,
          ]
            .filter(Boolean)
            .join("; ")
      : "Deployment readiness has not loaded yet.";
    const teardownInProgress = testDeployTeardownStatus === "running" ||
      (isEngagementTeardownAction(testDeployRunJob?.action) && ["queued", "running"].includes(testDeployRunJob?.status ?? ""));
    const finalCleanupStatus = testDeployRunJob ? pilotRunValue(testDeployRunJob, "finalCleanupStatus") : "not reported";
    const showTeardownActivity = teardownInProgress || teardownRequestUnconfirmed || hasTeardownActivity(testDeployRunJob);
    const teardownFailureEvent = testDeployRunJob?.status === "failed"
      ? [...testDeployRunJob.events].reverse().find((event) => event.message === "engagement teardown requires cleanup")
      : undefined;
    const teardownFailureDetail = typeof teardownFailureEvent?.data.detail === "string" ? teardownFailureEvent.data.detail : "";
    const teardownRemainingResources = Array.isArray(teardownFailureEvent?.data.remainingOwnedResources)
      ? teardownFailureEvent.data.remainingOwnedResources.filter((value): value is string => typeof value === "string")
      : [];
    const guidedDeploymentSteps = testDeployReadiness
      ? buildDeploymentSteps(
          testDeployReadiness,
          testDeployRunStatus,
          testDeployResult,
          testDeployRunJob,
          false,
          {
            sketchChain: linodeSketchChain,
            sketchChains: deployableInitialSketchChains,
            sketchJob: linodeSketchRunJob,
            sketchRunStatus: linodeSketchRunStatus,
            outboundChannels: engagementOperations?.outboundChannels ?? []
          }
        )
      : [];
    const teardownAwaitingParent = teardownRequestPending || teardownRequestUnconfirmed;
    const teardownActivitySteps = teardownAwaitingParent ? [] : buildTeardownSteps(testDeployRunJob, testDeployTeardownStatus);
    const infrastructureActivitySteps = showTeardownActivity ? teardownActivitySteps : guidedDeploymentSteps;
    const visibleInfrastructureActivitySteps = visibleDeploymentConsoleSteps(infrastructureActivitySteps);
    const activityHelp = showTeardownActivity
      ? teardownInProgress
        ? "Terraform destroy and cleanup verification are running for this engagement."
        : "Teardown completed and cleanup verification finished for this engagement."
      : "Follow the current deploy or inspection step for this engagement.";
    const activityStatus = teardownInProgress
      ? "running"
      : showTeardownActivity
        ? finalCleanupStatus
        : testDeployRunStatus === "running"
          ? "deploying"
          : testDeployRunStatus;
    const activeInfrastructureStep =
      infrastructureActivitySteps.find((step) => step.active) ??
      infrastructureActivitySteps.find((step) => step.status === "wip") ??
      infrastructureActivitySteps.find((step) => step.status === "failed") ??
      null;
    const infrastructureCommandActivity = teardownAwaitingParent ? null : currentInfrastructureCommandActivity(
      testDeployRunJob,
      infrastructureProgressNow
    );
    const publishedClock = !teardownAwaitingParent && testDeployRunJob?.action === "provider_keyed_mixed_published_cleanup"
      ? publishedTeardownTiming(testDeployRunJob, infrastructureProgressNow, engagementOperations) : null;
    const infrastructureConsoleTitle = showTeardownActivity
      ? "Infrastructure teardown console"
      : "Infrastructure deployment console";
    const infrastructureConsoleEmptyText = showTeardownActivity
      ? "Starting infrastructure teardown."
      : "Starting infrastructure deployment.";
    const infrastructureConsoleVisible = Boolean(
      infrastructureConsoleOpen &&
        (teardownAwaitingParent || !(["cleanup_required", "tearing_down"].includes(engagementOperations?.lifecycle?.state ?? "") &&
          !isEngagementTeardownAction(testDeployRunJob?.action))) &&
        (testDeployRunJob || testDeployRunStatus === "running" || testDeployRunStatus === "error" || showTeardownActivity)
    );
    const infrastructureConsoleSummary = teardownRequestUnconfirmed
      ? "Teardown could not be confirmed. Review Operations before trying again."
      : teardownRequestPending
      ? "Preparing teardown; waiting for the cleanup job."
      : infrastructureCommandActivity
      ? infrastructureCommandActivitySummary(infrastructureCommandActivity)
      : ["provider_keyed_mixed_zero_apply_cleanup", "provider_keyed_mixed_interrupted_cleanup", "provider_keyed_mixed_published_cleanup"].includes(testDeployRunJob?.action ?? "")
      ? mixedZeroApplyProgressMessage(testDeployRunJob)
      : testDeployTeardownStatus === "running" && showTeardownActivity
      ? activeInfrastructureStep
        ? `${activeInfrastructureStep.label} is running.`
        : infrastructureConsoleEmptyText
      : testDeployRunJob
        ? infrastructureJobProgressMessage(testDeployRunJob, showTeardownActivity, activeInfrastructureStep)
      : testDeployRunStatus === "running"
        ? infrastructureConsoleEmptyText
        : activityHelp;
    const expectedDisposableName = testDeployReadiness
      ? testDeployReadiness.expectedInstanceDisplayNames?.join(", ") ??
        testDeployReadiness.expectedInstanceDisplayName ??
        testDeployReadiness.expectedVcnDisplayName ??
        "disposable validation target"
      : "";
    const activeConnectionDetails = connectionDetailsFromJob(testDeployRunJob);
    const sshConfigStanza = normalizeOperatorSshConfig(engagementOperations?.sshConfig.stanza || buildSshConfigStanza(activeConnectionDetails));
    const sketchSshConfigStanza = buildSketchSshConfigStanza(engagementOperations, sketchSshKey);
    const sshConfigDownloadName = engagementOperations?.sshConfig.downloadName || `${selectedEngagement?.name?.toLowerCase() ?? "engagement"}-ssh-config`;
    const sshConfigDownloadHref = sshConfigStanza
      ? `data:text/plain;charset=utf-8,${encodeURIComponent(sshConfigStanza)}`
      : "";
    const overviewMarkdown = buildEngagementOverviewMarkdown(selectedEngagement, engagementOperations, sshConfigStanza);
    const overviewMarkdownDownloadName = markdownDownloadName(selectedEngagement, engagementOperations);
    const sketchChainsForEditor = sketchChainsWithIds(sketchIntent);
    const providerCatalogWarnings = Object.values(providerCatalogs).flatMap((catalog) => catalog?.warnings ?? []);
    const sketchActivityJobs = sketchDeploymentJobs.length ? sketchDeploymentJobs : linodeSketchRunJob ? [linodeSketchRunJob] : [];
    const sketchActivityStatus = sketchActivityJobs.some((job) => ["queued", "running"].includes(job.status))
      ? "running"
      : sketchActivityJobs.some((job) => job.status === "failed")
        ? "error"
        : sketchActivityJobs.length
          ? "ready"
          : linodeSketchRunStatus;
    const coreFinalCleanupStatus = testDeployRunJob
      ? pilotRunValue(testDeployRunJob, "finalCleanupStatus")
      : "";
    const teardownRecoveryRequired = coreFinalCleanupStatus === "cleanup_not_verified";
    const teardownRecoveryJobAvailable =
      isEngagementTeardownAction(engagementOperations?.teardownJob?.action) &&
      ["in_progress", "recoverable"].includes(engagementOperations.teardownJob.recoveryState ?? "") &&
      ["cleanup_required", "tearing_down"].includes(engagementOperations.lifecycle?.state ?? "") &&
      testDeployRunJob?.id === engagementOperations.teardownJob.id &&
      isRecoverableEngagementTeardownJob(testDeployRunJob, engagementOperations);
    const teardownReady =
      Boolean(testDeployRunJob) &&
      ["pending_operator_teardown", "cleanup_not_verified"].includes(coreFinalCleanupStatus) &&
      testDeployRunStatus !== "running";
    const coreDeployHeldForInspection = teardownReady;
    const activeCoreInfrastructure = teardownRecoveryJobAvailable || hasActiveCoreInfrastructure(engagementOperations, testDeployRunJob);
    const currentCoreDeployment = runningCoreDeploymentEvidence(engagementOperations);
    const currentCoreDeploymentLoaded =
      currentCoreDeployment !== null &&
      testDeployRunJob?.id === currentCoreDeployment.id &&
      testDeployRunJob?.action === currentCoreDeployment.action &&
      ["queued", "running"].includes(testDeployRunJob?.status ?? "");
    const retainedBootstrapRecoveryAvailable =
      legacySketchActionsAvailable && activeCoreInfrastructure && sketchChainRecords.some((chain) =>
        retainedSketchBootstrapEligible(
          chain,
          sketchDeploymentJobs.find((job) => job.id === chain.deployJobId) ?? null
        )
      );
    const infrastructureWorkflow = infrastructureWorkflowMode({
      operationsReady: engagementOperationsStatus === "ready" && engagementOperations?.engagementId === selectedEngagementId,
      operationsFailed: engagementOperationsStatus === "error",
      lifecycleState: engagementOperations?.lifecycle?.state ?? "unknown",
      teardownJobPresent: Boolean(engagementOperations?.teardownJob),
      teardownSelectionBlocked: ["ambiguous", "unavailable"].includes(engagementOperations?.teardownSelection?.state ?? ""),
      teardownJobComplete: engagementOperations?.teardownJob?.status === "succeeded" && engagementOperations.teardownJob.recoveryState === "complete",
      teardownRecoveryJobAvailable,
      teardownRequestPending,
      teardownRequestUnconfirmed,
      teardownJobLoading: teardownParentLoadStatus === "loading" && Boolean(engagementOperations?.teardownJob) &&
        ["in_progress", "recoverable"].includes(engagementOperations?.teardownJob?.recoveryState ?? ""),
      retainedBootstrapRecoveryAvailable,
      legacyChainCleanupAvailable: selectedEngagement?.sketchStateSchema !== "provider-keyed-v2" &&
        sketchChainRecords.some((chain) => chain.status === "failed"),
      activeCoreInfrastructure,
      currentCoreDeploymentLoaded
    });
    const coreRecreatePhrase = coreRecreateConfirmationPhrase(selectedEngagement);
    const coreRecreateReady =
      Boolean(testDeployReadiness) &&
      activeCoreInfrastructure &&
      coreRecreateConfirmation === coreRecreatePhrase &&
      testDeployRunStatus !== "running";
    const sketchIntentReady = deployableInitialSketchChains.length > 0;
    const backflipsConfirmationToken = backflipsApplyConfirmationToken();
    const backflipsApplyReady =
      Boolean(selectedEngagementId) &&
      backflipsServiceAction.confirmation === backflipsConfirmationToken &&
      backflipsServiceAction.status !== "running";
    const desktopConsoleAvailable = Boolean(desktopServiceAction.job || desktopServiceAction.message);
    const desktopConsoleLog = desktopConsoleText(desktopServiceAction.job, desktopServiceAction.message || "No Desktop job events are available yet.");
    const backflipsConsoleAvailable = Boolean(backflipsServiceAction.job || backflipsServiceAction.message);
    const backflipsConsoleLog = jobConsoleText(backflipsServiceAction.job, backflipsServiceAction.message || "No Backflips job events are available yet.", backflipsConsoleEventText);
    const webStaticApplyReady =
      Boolean(selectedEngagementId) &&
      webStaticServiceReady(webStaticServiceForm) &&
      webStaticServiceAction.status !== "running";
    const webStaticContentReviewed = Boolean(webStaticServiceAction.preview?.contentReview);
    const webStaticPlacements = (engagementOperations?.servicePlacements ?? []).filter((placement) => placement.serviceType === "web-static");
    const webStaticBindablePlacements = webStaticPlacements.filter((placement) => placement.status === "Configured");
    const webStaticActivePlacements = webStaticPlacements.filter((placement) => placement.status !== "Removed");
    const genericServicePlacements = (engagementOperations?.servicePlacements ?? []).filter((placement) => placement.serviceType === "generic");
    const genericServiceBindablePlacements = genericServicePlacements.filter((placement) => placement.status === "Active");
    const genericServiceActivePlacements = genericServicePlacements.filter((placement) => placement.status !== "Removed");
    const capabilityHttpBackendPlacements = (engagementOperations?.servicePlacements ?? []).filter(
      (placement) => placement.serviceType === "capability-http-backend" && placement.status === "Active"
    );
    const activeGenericServicePlacement = genericServiceForm.serviceId
      ? genericServicePlacements.find((placement) => placement.serviceId === genericServiceForm.serviceId) ?? null
      : null;
    const bindableServicePlacements = [
      ...webStaticBindablePlacements,
      ...genericServiceBindablePlacements,
      ...capabilityHttpBackendPlacements
    ];
    const bindableServiceOptions = bindableServicePlacements.filter((placement) =>
      inboundDraftUsesUdp(inboundChannelDraft)
        ? String(placement.protocol || "").toLowerCase() === "udp"
        : String(placement.protocol || "tcp").toLowerCase() !== "udp"
    );
    const activeWebStaticPlacement = activeWebStaticServiceId
      ? webStaticPlacements.find((placement) => placement.serviceId === activeWebStaticServiceId) ?? null
      : null;
    const activeWebStaticPlacementRemoved = activeWebStaticPlacement?.status === "Removed";
    const activeWebStaticPlacementRemoving = Boolean(
      activeWebStaticPlacement?.serviceId &&
        webStaticServiceRemovalAction.activeServiceId === activeWebStaticPlacement.serviceId
    );
    const openWebStaticComposer = () => {
      onResetWebStaticServiceAction();
      setWebStaticSiteComposerOpen(false);
      setActiveWebStaticServiceId(null);
      setActiveServiceComposer("web-static");
    };
    const openGenericComposer = () => {
      onUpdateGenericServiceAction({ activeServiceId: null, status: "idle", message: "" });
      onUpdateGenericServiceForm(blankGenericServiceForm());
      setGenericServiceEditorOpen(false);
      setActiveServiceComposer("generic");
    };
    const startNewGenericService = () => {
      onUpdateGenericServiceAction({ activeServiceId: null, status: "idle", message: "" });
      onUpdateGenericServiceForm(blankGenericServiceForm());
      setGenericServiceEditorOpen(true);
    };
    const configureGenericService = (placement: ServicePlacement) => {
      onUpdateGenericServiceAction({ activeServiceId: placement.serviceId ?? null, status: "idle", message: "" });
      onUpdateGenericServiceForm(genericServiceFormFromPlacement(placement));
      setGenericServiceEditorOpen(true);
      setActiveServiceComposer("generic");
    };
    const publishGenericService = (placement: ServicePlacement) => {
      const nextDraft = inboundDraftFromGenericPlacement(placement, engagementOperations, inboundEngagementName);
      if (!nextDraft) {
        onUpdateGenericServiceAction({ activeServiceId: placement.serviceId ?? null, status: "error", message: "Deploy a matching edge chain before publishing this service." });
        return;
      }
      setInboundChannelDraft(nextDraft);
      setInboundComposerOpen(true);
      setActiveChannelTab("inbound");
      setGenericServiceEditorOpen(false);
      setActiveServiceComposer(null);
      setActiveEngagementTab("channels");
    };
    const startNewWebStaticSite = () => {
      const siteName = nextWebStaticSiteName(webStaticPlacements);
      const proxyId = webStaticServiceForm.proxyId || "proxy01";
      onResetWebStaticServiceAction();
      setActiveWebStaticServiceId(null);
      onUpdateWebStaticServiceForm({
        proxyId,
        siteName,
        domain: `${siteName}.invalid`,
        internalPort: defaultWebStaticInternalPort,
        indexHtml: defaultWebStaticIndexHtml
      });
      setWebStaticSiteComposerOpen(true);
    };
    const configureWebStaticSite = (placement: ServicePlacement) => {
      const siteName = placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId) || "static-web";
      const restoredRequest = placement.status === "Removed" ? webStaticServiceRequestFromPlacement(placement, webStaticPlacements) : null;
      onResetWebStaticServiceAction();
      onUpdateWebStaticServiceForm({
        proxyId: restoredRequest?.proxyId || placement.hostId || "proxy01",
        siteName: restoredRequest?.siteName || siteName,
        domain: restoredRequest?.domain || placement.domain || `${siteName}.invalid`,
        internalPort: restoredRequest?.internalPort || defaultWebStaticInternalPort,
        indexHtml: defaultWebStaticIndexHtml
      });
      setActiveWebStaticServiceId(placement.serviceId ?? null);
      setWebStaticSiteComposerOpen(true);
    };
    const updateWebStaticProxy = (proxyId: string) => {
      onUpdateWebStaticServiceForm({ proxyId, internalPort: defaultWebStaticInternalPort });
    };
    const restoreConfiguredWebStaticSite = () => {
      if (!activeWebStaticPlacement) {
        return;
      }
      onRestoreWebStaticService(webStaticServiceRequest(webStaticServiceForm));
    };
    const publishWebStaticSite = (placement: ServicePlacement) => {
      const nextDraft = inboundDraftFromWebStaticPlacement(placement, engagementOperations, inboundEngagementName);
      if (!nextDraft) {
        onResetWebStaticServiceAction();
        onUpdateWebStaticServiceForm({
          proxyId: placement.hostId || "proxy01",
          siteName: placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId) || "static-web",
          domain: placement.domain || `${placement.siteName || "static-web"}.invalid`,
          internalPort: defaultWebStaticInternalPort,
          indexHtml: defaultWebStaticIndexHtml
        });
        return;
      }
      setInboundChannelDraft(nextDraft);
      setInboundComposerOpen(true);
      setActiveChannelTab("inbound");
      setActiveServiceComposer(null);
      setActiveEngagementTab("channels");
    };
    const channelRecordEnabled =
      Boolean(selectedEngagementId) &&
      engagementOperationsStatus !== "saving" &&
      (inboundChannelReady(inboundChannelDraft) || outboundChannelReady(outboundChannelDraft));
    const linodeSketchGuardrailMessage = coreDeployHeldForInspection
      ? sketchIntentReady
        ? "Sketch provisioning starts automatically after core homebase and proxies are ready."
        : "Select a supported same-provider sketch chain. Barragan will use the default provider credentials."
      : "Sketch provisioning waits for core homebase and proxies so later configuration can use proxy jump paths.";
    const teardownPhrase = engagementTeardownPreview?.confirmationPhrase ?? teardownConfirmationPhrase(selectedEngagement);
    const teardownConfirmed = engagementTeardownPreviewStatus === "ready" && Boolean(engagementTeardownPreview) && testDeployTeardownConfirmation === teardownPhrase;
    // A failed chain can retain provider nodes specifically so the operator can
    // inspect its job, retry the readiness bootstrap, or tear it down. It is
    // not a live route, but hiding it here made that recovery impossible.
    const visibleSketchChainRecords = sketchChainRecords.filter(
      (chain) => !["aborted", "destroyed"].includes(chain.status)
    );
    const renderLiveSketchChainLifecycle = () => (
      <section className="table-panel embedded sketch-chain-lifecycle" aria-label="Live sketch chain lifecycle">
        <div className="section-heading table-section-heading">
          <div>
            <h3>Live sketch chain lifecycle</h3>
            <p>{legacySketchActionsAvailable ? "Existing chains stay locked after deployment. Add replacement chains without changing deployed chains." : "Keyed chains are managed by the reviewed deployment. Published chains support the reviewed edge append workflow."}</p>
          </div>
          <div className="section-actions">
            <span>{visibleSketchChainRecords.length} chains · {mixedSketchAwaitingPublication ? "publication pending" : sketchChainRecordsStatus}</span>
            {linodeSketchRunJob ? (
              <button className="secondary-action compact" onClick={() => onOpenLifecycleConsole("sketch")} type="button">
                <ListChecks aria-hidden="true" size={14} />
                Log
              </button>
            ) : null}
          </div>
        </div>
        {sketchChainMessage ? <div className="inline-warning" role="status">{sketchChainMessage}</div> : null}
        <div className="workflow-actions">
          {legacySketchActionsAvailable && activeInfrastructureProxyOptions.map((proxy) => (
            <button
              className="secondary-action compact"
              disabled={providerCatalogStatus !== "ready" || !selectedEngagementId || sketchChainRecordsStatus === "saving"}
              key={`replacement-${proxy}`}
              onClick={() => onCreateReplacementSketchChain(proxy)}
              type="button"
            >
              Add {proxy} Chain
            </button>
          ))}
        </div>
        {selectedEngagementId && !mixedSketchAwaitingPublication && visibleSketchChainRecords.length === 2 &&
          visibleSketchChainRecords.every((chain) => chain.status === "deployed" && chain.nodes.length === 2) &&
          visibleSketchChainRecords.some((chain) => chain.middleProvider === "digitalocean" && chain.edgeProvider === "digitalocean") &&
          visibleSketchChainRecords.some((chain) => chain.middleProvider === "linode" && chain.edgeProvider === "linode") ? (
            <MixedAppendReview key={selectedEngagementId} engagementId={selectedEngagementId}
              chains={visibleSketchChainRecords} catalogs={providerCatalogs} />
          ) : null}
        {visibleSketchChainRecords.length ? (
          <div className="chain-lifecycle-list">
            {visibleSketchChainRecords.map((chain) => {
              const chainTeardownPhrase = `teardown-${chain.chainId}`;
              const chainCancelPhrase = `cancel-${chain.chainId}`;
              const stopPhrase = `stop-${chain.chainId}`;
              const startPhrase = `start-${chain.chainId}`;
              const powerConfirmation = sketchChainPowerConfirmations[chain.chainId] ?? "";
              const isTeardownTarget = sketchChainTeardownTarget === chain.chainId;
              const isCancelTarget = sketchChainCancelTarget === chain.chainId;
              const policyErrors = sketchChainRegionPolicyErrors(chain, providerCatalogs);
              const hasProviderDrift =
                ["deploying", "starting", "stopping", "tearing_down"].includes(chain.status) &&
                chain.nodes.length === 0 &&
                Boolean(engagementOperations?.providerFindings?.length);
              const bootstrapJob = sketchDeploymentJobs.find((job) => job.id === chain.deployJobId) ?? null;
              const bootstrapNeedsReview = sketchBootstrapReconciliationRequired(bootstrapJob);
              const bootstrapQuiescenceUnproved = bootstrapJob?.events.some((event) => event.data.localQuiescenceUnproved === true) ?? false;
              const canRetryBootstrap = legacySketchActionsAvailable && retainedSketchBootstrapEligible(chain, bootstrapJob);
              return (
                <div className="workflow-panel sketch-chain-card locked" key={chain.chainId}>
                  <div className="section-heading">
                    <div>
                      <h3>{chain.chainId}</h3>
                      <p>{chain.assignedProxy}{" -> middle -> "}{(chain.edges?.length ? chain.edges : [{ id: "edge-01", provider: chain.edgeProvider, region: chain.edgeRegion, size: chain.edgeSize }]).map((edge) => `${edge.id} ${edge.provider}/${edge.region}`).join("; ")} · {chain.status}</p>
                    </div>
                    <div className="section-actions">
                      <span className={chain.burned || bootstrapNeedsReview ? "status error" : "status ready"}>
                        {chain.burned ? "Burned" : bootstrapNeedsReview ? "Needs review" : mixedSketchAwaitingPublication ? "Publication pending" : "Available"}
                      </span>
                      <span>{legacySketchActionsAvailable ? chain.status === "pending" ? "Editable until deployed" : "Locked after deployment" : "Managed by deployment"}</span>
                    </div>
                  </div>
                  {legacySketchActionsAvailable && chain.status === "pending" && policyErrors.length ? (
                    <div className="inline-warning" role="status">
                      This pending chain is outside the current sketch region allowlist: {policyErrors.join("; ")}. Choose an allowed region or update Global Settings before deploying.
                    </div>
                  ) : null}
                  {bootstrapNeedsReview ? (
                    <div className="inline-warning" role="status">
                      Bootstrap execution stopped. Remote work may still be running; reconciliation is required before retrying. Review the retained job log.
                      {bootstrapQuiescenceUnproved ? " Local command termination is unproved; chain teardown is blocked until reviewed." : " Provider nodes are retained; teardown remains available."}
                    </div>
                  ) : canRetryBootstrap ? (
                    <div className="inline-warning" role="status">
                      The last deployment did not reach readiness. Provider nodes and failed bootstrap parent {chain.deployJobId} are retained; review the log, then retry this chain or tear it down.
                    </div>
                  ) : chain.status === "failed" ? (
                    <div className="inline-warning" role="status">
                      This failed chain has no complete retained bootstrap record. Review the log or tear it down; Barragan will not start a new provider deployment from this state.
                    </div>
                  ) : null}
                  {hasProviderDrift ? (
                    <div className="inline-warning" role="status">
                      Provider inventory still sees infrastructure for this engagement, but this chain has no usable node records. Use Provider Tracking to review and safely recover the Barragan-owned resources.
                      <div className="section-actions">
                        <button className="secondary-action compact" onClick={() => setActiveEngagementTab("overview")} type="button">
                          Review Provider Recovery
                        </button>
                      </div>
                    </div>
                  ) : null}
                  {legacySketchActionsAvailable && chain.status === "pending" ? (
                    <div className="detail-grid">
                      <label>
                        <span>Middle provider</span>
                        <select
                          aria-label={`${chain.chainId} live middle provider`}
                          disabled={providerCatalogStatus !== "ready"}
                          onChange={(event) => {
                            const defaults = providerDefaults(providerCatalogs, event.target.value);
                            onUpdateSketchChainRecord(chain, {
                              middleProvider: event.target.value,
                              middleRegion: defaults.region,
                              middleSize: defaults.size
                            });
                          }}
                          value={chain.middleProvider}
                        >
                          {sketchProviderOptions.map((provider) => (
                            <option key={provider} value={provider}>{provider}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span>Middle region</span>
                        <select
                          aria-label={`${chain.chainId} live middle region`}
                          disabled={providerCatalogStatus !== "ready"}
                          onChange={(event) =>
                            onUpdateSketchChainRecord(chain, {
                              middleRegion: event.target.value,
                              middleSize: sizeForRegion(providerCatalogs, chain.middleProvider, event.target.value, chain.middleSize)
                            })
                          }
                          value={chain.middleRegion}
                        >
                          {regionOptionsWithCurrentPolicyMarker(providerCatalogs, chain.middleProvider, chain.middleRegion).map((region) => (
                            <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span>Default edge provider</span>
                        <select
                          aria-label={`${chain.chainId} live edge provider`}
                          disabled={providerCatalogStatus !== "ready"}
                          onChange={(event) => {
                            const defaults = providerDefaults(providerCatalogs, event.target.value);
                            const edges = effectiveSketchChainEdges(chain).map((edge) => ({ ...edge, provider: event.target.value, region: defaults.region, size: defaults.size }));
                            onUpdateSketchChainRecord(chain, {
                              edgeProvider: event.target.value,
                              edgeRegion: defaults.region,
                              edgeSize: defaults.size,
                              edges
                            });
                          }}
                          value={chain.edgeProvider}
                        >
                          {sketchProviderOptions.map((provider) => (
                            <option key={provider} value={provider}>{provider}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span>Default edge region</span>
                        <select
                          aria-label={`${chain.chainId} live default edge region`}
                          disabled={providerCatalogStatus !== "ready"}
                          onChange={(event) => {
                            const size = sizeForRegion(providerCatalogs, chain.edgeProvider, event.target.value, chain.edgeSize);
                            const edges = effectiveSketchChainEdges(chain).map((edge) => ({ ...edge, provider: chain.edgeProvider, region: event.target.value, size }));
                            onUpdateSketchChainRecord(chain, {
                              edgeRegion: event.target.value,
                              edgeSize: size,
                              edges
                            });
                          }}
                          value={chain.edgeRegion}
                        >
                          {regionOptionsWithCurrentPolicyMarker(providerCatalogs, chain.edgeProvider, chain.edgeRegion).map((region) => (
                            <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        <span>Edge nodes</span>
                        <input
                          aria-label={`${chain.chainId} live edge nodes`}
                          disabled={providerCatalogStatus !== "ready"}
                          max={10}
                          min={1}
                          onChange={(event) =>
                            onUpdateSketchChainRecord(chain, {
                              edgeCount: Math.max(1, Math.min(10, Number.parseInt(event.target.value || "1", 10) || 1))
                            })
                          }
                          type="number"
                          value={chain.edgeCount}
                        />
                      </label>
                      {chain.edgeCount > 1 ? (
                        <div className="wide-field" aria-label={`${chain.chainId} live edge rows`}>
                          <span>Individual edge placement</span>
                          <p>Each edge may use its own provider, region, and size. The default controls reset every edge row.</p>
                          {effectiveSketchChainEdges(chain).map((edge, edgeIndex) => (
                            <div className="form-grid" key={edge.id}>
                              <strong>Edge {String(edgeIndex + 1).padStart(2, "0")}</strong>
                              <label>
                                <span>Provider</span>
                                <select
                                  aria-label={`${chain.chainId} live edge ${String(edgeIndex + 1).padStart(2, "0")} provider`}
                                  disabled={providerCatalogStatus !== "ready"}
                                  onChange={(event) => {
                                    const defaults = providerDefaults(providerCatalogs, event.target.value);
                                    onUpdateSketchChainRecord(chain, updateEffectiveSketchEdge(chain, edgeIndex, {
                                      provider: event.target.value,
                                      region: defaults.region,
                                      size: defaults.size
                                    }));
                                  }}
                                  value={edge.provider}
                                >
                                  {sketchProviderOptions.map((provider) => (
                                    <option key={provider} value={provider}>{provider}</option>
                                  ))}
                                </select>
                              </label>
                              <label>
                                <span>Region</span>
                                <select
                                  aria-label={`${chain.chainId} live edge ${String(edgeIndex + 1).padStart(2, "0")} region`}
                                  disabled={providerCatalogStatus !== "ready"}
                                  onChange={(event) => onUpdateSketchChainRecord(
                                    chain,
                                    updateEffectiveSketchEdge(chain, edgeIndex, {
                                      provider: edge.provider,
                                      region: event.target.value,
                                      size: sizeForRegion(providerCatalogs, edge.provider, event.target.value, edge.size)
                                    })
                                  )}
                                  value={edge.region}
                                >
                                  {regionOptionsWithCurrentPolicyMarker(providerCatalogs, edge.provider, edge.region).map((region) => (
                                    <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>
                                  ))}
                                </select>
                              </label>
                              <label>
                                <span>Size/shape</span>
                                <select
                                  aria-label={`${chain.chainId} live edge ${String(edgeIndex + 1).padStart(2, "0")} size`}
                                  disabled={providerCatalogStatus !== "ready"}
                                  onChange={(event) => onUpdateSketchChainRecord(chain, updateEffectiveSketchEdge(chain, edgeIndex, { size: event.target.value }))}
                                  value={edge.size}
                                >
                                  {sizeOptions(providerCatalogs, edge.provider, edge.region, edge.size).map((size) => (
                                    <option disabled={!size.available} key={size.id} value={size.id}>{sizeLabel(size)}</option>
                                  ))}
                                </select>
                              </label>
                            </div>
                          ))}
                        </div>
                      ) : null}
                      <details className="wide-field">
                        <summary>Advanced sketch settings</summary>
                        <label>
                          <span>Middle size/shape</span>
                          <select
                            aria-label={`${chain.chainId} live middle size`}
                            disabled={providerCatalogStatus !== "ready"}
                            onChange={(event) => onUpdateSketchChainRecord(chain, { middleSize: event.target.value })}
                            value={chain.middleSize}
                          >
                            {sizeOptions(providerCatalogs, chain.middleProvider, chain.middleRegion, chain.middleSize).map((size) => (
                              <option disabled={!size.available} key={size.id} value={size.id}>{sizeLabel(size)}</option>
                            ))}
                          </select>
                        </label>
                        <label>
                          <span>Default edge size/shape</span>
                          <select
                            aria-label={`${chain.chainId} live edge size`}
                            disabled={providerCatalogStatus !== "ready"}
                            onChange={(event) => {
                              const edges = effectiveSketchChainEdges(chain).map((edge) => ({ ...edge, size: event.target.value }));
                              onUpdateSketchChainRecord(chain, { edges, edgeProvider: edges[0].provider, edgeRegion: edges[0].region, edgeSize: edges[0].size });
                            }}
                            value={chain.edgeSize}
                          >
                            {sizeOptions(providerCatalogs, chain.edgeProvider, chain.edgeRegion, chain.edgeSize).map((size) => (
                              <option disabled={!size.available} key={size.id} value={size.id}>{sizeLabel(size)}</option>
                            ))}
                          </select>
                        </label>
                      </details>
                    </div>
                  ) : (
                    <div className="detail-grid">
                      <div>
                        <span>Middle</span>
                        <strong>{chain.middleProvider} · {chain.middleRegion} · {chain.middleSize}</strong>
                      </div>
                      <div>
                        <span>Edge</span>
                        <strong>{(chain.edges?.length ? chain.edges : [{ id: "edge-01", provider: chain.edgeProvider, region: chain.edgeRegion, size: chain.edgeSize }]).map((edge) => `${edge.id} ${edge.provider} · ${edge.region} · ${edge.size}`).join("; ")}</strong>
                      </div>
                      <div>
                        <span>Nodes</span>
                        <strong>{chain.nodes.length ? `${chain.nodes.length} recorded` : "Not Deployed"}</strong>
                      </div>
                      <div>
                        <span>Burned note</span>
                        <strong>{chain.burnedNote || "N/A"}</strong>
                      </div>
                    </div>
                  )}
                  {selectedEngagementId && !mixedSketchAwaitingPublication && chain.status === "deployed" &&
                    chain.middleProvider === "digitalocean" && chain.edgeProvider === "digitalocean" &&
                    chain.edgeCount === 1 && chain.nodes.length === 2 &&
                    !visibleSketchChainRecords.some((other) => other.chainId !== chain.chainId &&
                      other.middleProvider === "linode" && other.edgeProvider === "linode" && other.status === "deployed") ? (
                      <KeyedEdgeAppendReview engagementId={selectedEngagementId}
                        chain={chain} />
                    ) : null}
                  {legacySketchActionsAvailable && chain.status === "deployed" && effectiveSketchChainEdges(chain).length >= 2 ? (() => {
                    const finalEdge = effectiveSketchChainEdges(chain).at(-1)!;
                    const transitionKey = `${chain.chainId}:retire`;
                    const phrase = `retire-edge-${chain.chainId}-${finalEdge.id}`;
                    return (
                      <div className="teardown-confirmation" role="group" aria-label={`${chain.chainId} final edge retirement`}>
                        <p>Retire only {finalEdge.id}. Barragan removes its outbound profiles first and reviews Terraform to ensure the middle and sibling edge stay untouched.</p>
                        <label>
                          <span>Type {phrase} to retire the final edge</span>
                          <input aria-label={`${chain.chainId} retire final edge phrase`} onChange={(event) => setSketchEdgeTransitionConfirmations((current) => ({ ...current, [transitionKey]: event.target.value }))} placeholder={phrase} value={sketchEdgeTransitionConfirmations[transitionKey] ?? ""} />
                        </label>
                        <button className="secondary-action compact danger" disabled={sketchChainRecordsStatus === "saving" || sketchEdgeTransitionConfirmations[transitionKey] !== phrase} onClick={() => onRetireSketchChainFinalEdge(chain)} type="button">Retire Final Edge</button>
                      </div>
                    );
                  })() : null}
                  {legacySketchActionsAvailable && chain.status === "deployed" && effectiveSketchChainEdges(chain).length === 1 ? (() => {
                    const existing = effectiveSketchChainEdges(chain);
                    const region = sketchEdgeReplacementRegions[chain.chainId] ?? "";
                    const transitionKey = `${chain.chainId}:replace`;
                    const phrase = `replace-edge-${chain.chainId}-${region}`;
                    return (
                      <div className="teardown-confirmation" role="group" aria-label={`${chain.chainId} replacement edge`}>
                        <p>Add one replacement final edge in a different region. Its outbound profile will be configured and validated automatically after bootstrap.</p>
                        <label>
                          <span>Replacement region</span>
                          <select aria-label={`${chain.chainId} replacement edge region`} onChange={(event) => setSketchEdgeReplacementRegions((current) => ({ ...current, [chain.chainId]: event.target.value }))} value={region}>
                            <option value="">Choose a different region</option>
                            {regionOptionsWithCurrentPolicyMarker(providerCatalogs, chain.edgeProvider, chain.edgeRegion).filter((candidate) => !existing.some((edge) => edge.region === candidate.id)).map((candidate) => <option disabled={!candidate.available} key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
                          </select>
                        </label>
                        <label>
                          <span>Type {phrase} to add the replacement edge</span>
                          <input aria-label={`${chain.chainId} replacement edge phrase`} disabled={!region} onChange={(event) => setSketchEdgeTransitionConfirmations((current) => ({ ...current, [transitionKey]: event.target.value }))} placeholder={phrase} value={sketchEdgeTransitionConfirmations[transitionKey] ?? ""} />
                        </label>
                        <button className="primary-action compact" disabled={!region || sketchChainRecordsStatus === "saving" || sketchEdgeTransitionConfirmations[transitionKey] !== phrase} onClick={() => onReplaceSketchChainFinalEdge(chain)} type="button">Add Replacement Edge</button>
                      </div>
                    );
                  })() : null}
                  {legacySketchActionsAvailable ? <div className="workflow-actions">
                    {legacySketchActionsAvailable && ((chain.status === "pending" && !bootstrapNeedsReview) || canRetryBootstrap) ? (
                      <button
                        className="primary-action"
                        disabled={sketchChainRecordsStatus === "saving" || (
                          chain.status === "pending" && (providerCatalogStatus !== "ready" || policyErrors.length > 0)
                        )}
                        onClick={() => onDeploySketchChainRecord(chain)}
                        type="button"
                      >
                        {canRetryBootstrap ? "Retry Bootstrap" : "Deploy New Chain"}
                      </button>
                    ) : null}
                    {legacySketchActionsAvailable && chain.status === "pending" ? (
                      <button
                        className="secondary-action compact danger"
                        disabled={sketchChainRecordsStatus === "saving"}
                        onClick={() => {
                          setSketchChainCancelTarget(chain.chainId);
                          setSketchChainCancelConfirmation("");
                        }}
                        type="button"
                      >
                        Cancel
                      </button>
                    ) : null}
                    <button
                      className="secondary-action compact"
                      disabled={sketchChainRecordsStatus === "saving"}
                      onClick={() => onMarkSketchChainBurned(chain)}
                      type="button"
                    >
                      {chain.burned ? "Clear Burned Flag" : "Mark Burned"}
                    </button>
                    {chain.status === "deployed" ? (
                      <>
                        <label>
                          <span>Type {stopPhrase}</span>
                          <input
                            aria-label={`${chain.chainId} stop phrase`}
                            onChange={(event) => onUpdateSketchChainPowerConfirmation(chain.chainId, event.target.value)}
                            placeholder={stopPhrase}
                            value={powerConfirmation}
                          />
                        </label>
                        <button
                          className="secondary-action compact"
                          disabled={sketchChainRecordsStatus === "saving" || powerConfirmation !== stopPhrase}
                          onClick={() => onStopSketchChainRecord(chain)}
                          type="button"
                        >
                          Stop Nodes
                        </button>
                      </>
                    ) : null}
                    {chain.status === "stopped" ? (
                      <>
                        <label>
                          <span>Type {startPhrase}</span>
                          <input
                            aria-label={`${chain.chainId} start phrase`}
                            onChange={(event) => onUpdateSketchChainPowerConfirmation(chain.chainId, event.target.value)}
                            placeholder={startPhrase}
                            value={powerConfirmation}
                          />
                        </label>
                        <button
                          className="secondary-action compact"
                          disabled={sketchChainRecordsStatus === "saving" || powerConfirmation !== startPhrase}
                          onClick={() => onStartSketchChainRecord(chain)}
                          type="button"
                        >
                          Start Nodes
                        </button>
                      </>
                    ) : null}
                    <button
                      className="secondary-action compact danger"
                      disabled={bootstrapQuiescenceUnproved || !["deployed", "failed", "stopped"].includes(chain.status) || sketchChainRecordsStatus === "saving"}
                      onClick={() => {
                        setSketchChainTeardownTarget(chain.chainId);
                        setSketchChainTeardownConfirmation("");
                      }}
                      type="button"
                    >
                      Tear Down Chain
                    </button>
                  </div> : null}
                  {legacySketchActionsAvailable && isCancelTarget ? (
                    <div className="teardown-confirmation" role="group" aria-label={`${chain.chainId} cancel confirmation`}>
                      <label>
                        <span>Type {chainCancelPhrase} to cancel this pending chain</span>
                        <input
                          aria-label={`${chain.chainId} cancel phrase`}
                          onChange={(event) => setSketchChainCancelConfirmation(event.target.value)}
                          placeholder={chainCancelPhrase}
                          value={sketchChainCancelConfirmation}
                        />
                      </label>
                      <button
                        className="secondary-action danger"
                        disabled={sketchChainCancelConfirmation !== chainCancelPhrase}
                        onClick={() => onCancelSketchChainRecord(chain)}
                        type="button"
                      >
                        Confirm Cancel
                      </button>
                      <button
                        className="secondary-action compact"
                        onClick={() => {
                          setSketchChainCancelTarget(null);
                          setSketchChainCancelConfirmation("");
                        }}
                        type="button"
                      >
                        Keep Chain
                      </button>
                    </div>
                  ) : null}
                  {legacySketchActionsAvailable && isTeardownTarget ? (
                    <div className="teardown-confirmation" role="group" aria-label={`${chain.chainId} teardown confirmation`}>
                      <label>
                        <span>Type {chainTeardownPhrase} to confirm chain tear down</span>
                        <input
                          aria-label={`${chain.chainId} teardown phrase`}
                          onChange={(event) => setSketchChainTeardownConfirmation(event.target.value)}
                          placeholder={chainTeardownPhrase}
                          value={sketchChainTeardownConfirmation}
                        />
                      </label>
                      <button
                        className="secondary-action danger"
                        disabled={sketchChainTeardownConfirmation !== chainTeardownPhrase}
                        onClick={() => onTeardownSketchChainRecord(chain)}
                        type="button"
                      >
                        Confirm Chain Tear Down
                      </button>
                      <button
                        className="secondary-action compact"
                        onClick={() => {
                          setSketchChainTeardownTarget(null);
                          setSketchChainTeardownConfirmation("");
                        }}
                        type="button"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="empty-state inline">
            <h3>No live sketch chains recorded</h3>
            <p>Initial deployment will create locked chain records. Replacement chains can be added here after deployment.</p>
          </div>
        )}
        <p className="guardrail-hint">{legacySketchActionsAvailable ? "Stop and start use provider power APIs only; Barragan does not SSH directly to sketch middle or edge nodes. Marking a chain burned only records operator state; it does not change nodes or channel references." : "Wait for canonical publication before using channels or reviewing an edge append. Use the engagement teardown to remove keyed infrastructure."}</p>
      </section>
    );
    const coreInfrastructureJob = testDeployRunJob?.action === "pilot_standard_rti_guarded_execute" ? testDeployRunJob : null;
    const recordedCoreJob = engagementOperations?.coreJob?.action === "pilot_standard_rti_guarded_execute" ? engagementOperations.coreJob : null;
    const renderCurrentCoreInfrastructure = (historical = false) => !historical && (teardownAwaitingParent || isEngagementTeardownAction(testDeployRunJob?.action)) ? null : (
      <section className="pilot-run-history" aria-label={historical ? "Historical core infrastructure" : "Current core infrastructure"}>
        <div className="section-heading">
          <h3>{historical ? "Historical Core Infrastructure" : "Current Core Infrastructure"}</h3>
          <div className="section-actions">
            <span>{coreInfrastructureJob?.status ?? recordedCoreJob?.status ?? engagementOperationsStatus}</span>
            {coreInfrastructureJob ? (
              <button className="secondary-action compact" onClick={onRefreshTestDeploymentRun} type="button">
                Refresh
              </button>
            ) : null}
          </div>
        </div>
        {historical ? <p className="guardrail-hint">These records describe the deployment before verified cleanup. Recorded addresses and job outcomes do not indicate running resources.</p> : null}
        {historical && !coreInfrastructureJob && recordedCoreJob ? (
          <div className="detail-grid test-deploy-grid">
            <div><span>Job ID</span><strong>{recordedCoreJob.id}</strong></div>
            <div><span>Deployment status</span><strong>{recordedCoreJob.status}</strong></div>
          </div>
        ) : null}
        {coreInfrastructureJob ? (
          <>
            <div className="detail-grid test-deploy-grid">
              <div>
                <span>Job ID</span>
                <strong>{coreInfrastructureJob.id}</strong>
              </div>
              <div>
                <span>Workspace</span>
                <strong>{pilotRunValue(coreInfrastructureJob, "workspace")}</strong>
              </div>
              <div>
                <span>Infrastructure</span>
                <strong>{pilotRunValue(coreInfrastructureJob, "mutationStatus")}</strong>
              </div>
              <div>
                <span>Ansible</span>
                <strong>{pilotRunValue(coreInfrastructureJob, "ansibleStatus")}</strong>
              </div>
              <div>
                <span>Tear down</span>
                <strong>{pilotRunValue(coreInfrastructureJob, "finalCleanupStatus")}</strong>
              </div>
            </div>
            {activeConnectionDetails.length > 0 ? (
              <div className="table-panel embedded" aria-label={historical ? "Historical connection details" : "Connection details"}>
                <TableHeader columns={["Host", "Public SSH", "Private IP", "Services"]} />
                {activeConnectionDetails.map((host) => (
                  <div className="table-row" key={`connection-${host.displayName}`}>
                    <span>{host.displayName}</span>
                    <code>{host.sshCommand}</code>
                    <span>{host.privateIp}</span>
                    <span>{host.services.join(", ")}</span>
                  </div>
                ))}
              </div>
            ) : null}
          </>
        ) : engagementOperations?.coreInfrastructure.length ? (
          <div className="table-panel embedded" aria-label="Recorded core hosts">
            <TableHeader columns={["Host", "Public IP", "Private IP", "Status"]} />
            {engagementOperations.coreInfrastructure.map((host) => (
              <div className="table-row" key={`running-core-${host.hostname}`}>
                <span>{host.hostname}</span>
                <span>{host.publicIp || "N/A"}</span>
                <span>{host.privateIp || "N/A"}</span>
                <span>{host.lifecycleState || host.status || host.health?.status || "unknown"}</span>
              </div>
            ))}
          </div>
        ) : (
          <OperationsEmptyState message={historical ? "Detailed core deployment output is not loaded. Review engagement History for recorded events." : "No active core infrastructure is recorded for this engagement."} />
        )}
      </section>
    );
    const renderRunningInfrastructureWorkflow = (teardownRecoveryOnly = false) => (
      <section className="workflow-step-group running-infrastructure-group" aria-label="Manage running infrastructure">
        <section className="workflow-panel workflow-section-heading">
          <div>
            <h3>{teardownRequestPending ? "Preparing teardown" : teardownRecoveryOnly ? isEngagementTeardownAction(testDeployRunJob?.action) && ["queued", "running"].includes(testDeployRunJob?.status ?? "") ? "Infrastructure teardown in progress" : "Recover Infrastructure Cleanup" : "Manage Running Infrastructure"}</h3>
            <p>{teardownRequestPending ? "Barragan is checking the confirmed scope. Wait for the cleanup job before starting another teardown." : teardownRecoveryOnly
              ? ["queued", "running"].includes(testDeployRunJob?.status ?? "") ? "Barragan is advancing the recorded teardown. Keep this page open to follow progress." : "Resume the exact recorded comprehensive teardown without exposing unrelated infrastructure mutations."
              : legacySketchActionsAvailable ? "Add, remove, stop, start, or replace live resources without rerolling homebase or proxies." : "Follow deployment publication, review supported edge appends, or tear down this engagement."}</p>
          </div>
        </section>
        <div className="workflow-step-body">
          {teardownRequestPending ? (
            <section className="workflow-panel" role="status" aria-label="Teardown request progress">
              <strong>Waiting for the cleanup job</strong>
              <p>No cleanup job has been confirmed yet. This view will update when it is ready.</p>
            </section>
          ) : teardownRecoveryOnly && testDeployRunJob?.action === "provider_keyed_mixed_published_cleanup" ? (
            <section className="workflow-panel" role="status" aria-label="Teardown worker progress">
              <strong>{mixedZeroApplyProgressMessage(testDeployRunJob)}</strong>
              <p>{testDeployRunJob.activeChild ? `${testDeployRunJob.activeChild.message} (${testDeployRunJob.activeChild.status})` : testDeployRunJob.activeChildState === "ambiguous" ? "Multiple worker records match; review the recorded teardown progress." : "Waiting for the next recorded teardown step."}</p>
              <p>{testDeployRunJob.dispatch?.heartbeatAt ? `Worker heartbeat: ${new Date(testDeployRunJob.dispatch.heartbeatAt).toLocaleString()}` : "Worker heartbeat is not available."} {testDeployRunJob.dispatch?.claimState === "live" ? "Worker claim is active." : "The recorded worker claim needs review; do not start another teardown."}</p>
            </section>
          ) : null}
          {renderCurrentCoreInfrastructure()}
          {mixedSketchAwaitingPublication ? (
            <div className="inline-warning" role="status">
              {engagementOperations?.mixedInitialJob?.phase === "awaiting_mixed_host_proof"
                ? "Both provider plans were applied. Host verification is pending; wait for both chains to be published before using channels."
                : "Sketch deployment is not complete. Provider setup and host verification may still be running. Wait for both chains to be published before using channels."}
            </div>
          ) : null}
          <section className="pilot-run-history infrastructure-lifecycle-panel" aria-label="Infrastructure lifecycle">
            <div className="section-heading">
              <div>
                <h3>Infrastructure lifecycle</h3>
                <p>Lifecycle actions apply to the deployed instances without changing engagement metadata.</p>
              </div>
              <span>{mixedSketchAwaitingPublication
                ? engagementOperations?.mixedInitialJob?.phase === "awaiting_mixed_host_proof" ? "host verification pending" : "waiting for Sketch"
                : teardownReady ? "ready for engagement operations" : activityStatus}</span>
            </div>
            <div className="workflow-actions">
              {!teardownRecoveryOnly ? <button className="secondary-action" disabled type="button">Start Instances</button> : null}
              {!teardownRecoveryOnly ? <button className="secondary-action" disabled type="button">Stop Instances</button> : null}
              {!teardownRecoveryOnly ? <button className="secondary-action" disabled type="button">Archive Deployment</button> : null}
              <button
                className="secondary-action danger"
                disabled={!teardownReady || testDeployTeardownStatus === "confirming"}
                onClick={onBeginTestDeploymentTeardown}
                type="button"
              >
                {teardownRecoveryRequired ? "Retry Tear Down" : "Tear Down Infrastructure"}
              </button>
            </div>
            <p className="guardrail-hint">Next: add team users, apply capabilities, then configure channels, DNS, and certificates as needed. Start, stop, and archive require provider-backed lifecycle jobs and are not enabled yet.</p>
            {testDeployTeardownStatus === "confirming" && testDeployRunJob ? (
              <div className="teardown-confirmation" role="group" aria-label="Confirm tear down">
                <div className="detail-grid test-deploy-grid deployment-checkout-review" aria-label="Engagement teardown scope">
                  {engagementTeardownPreviewStatus === "loading" ? (
                    <div><span>Cleanup scope</span><strong>Loading current Barragan-owned resources…</strong></div>
                  ) : engagementTeardownPreviewStatus === "error" ? (
                    <div><span>Cleanup scope</span><strong>Could not load the teardown scope. Cancel and try again.</strong></div>
                  ) : engagementTeardownPreview ? engagementTeardownPreview.orderedScope.map((scope, index) => (
                    <div key={scope.id}>
                      <span>{index + 1}. {scope.label}</span>
                      <strong>{engagementTeardownScopeSummary(scope)}</strong>
                    </div>
                  )) : null}
                </div>
                <p className="guardrail-hint">{isMixedZeroApplyTeardownPreview(engagementTeardownPreview)
                  ? "No Sketch nodes were applied. Barragan verifies the saved provider plans remained unapplied, destroys core, checks the former public SSH targets from Inspector, and retires Inspector. The engagement configuration remains available for redeploy."
                  : "Barragan removes owned infrastructure and independent public bindings, verifies absence, then retires Inspector. The engagement configuration remains available for redeploy."}</p>
                <label>
                  <span>Type {teardownPhrase} to confirm tear down</span>
                  <input
                    aria-label="Confirm tear down phrase"
                    onChange={(event) => setTestDeployTeardownConfirmation(event.target.value)}
                    placeholder={teardownPhrase}
                    value={testDeployTeardownConfirmation}
                  />
                </label>
                <button
                  className="secondary-action danger"
                  disabled={!teardownConfirmed}
                  onClick={onTeardownTestDeploymentRun}
                  type="button"
                >
                  Confirm Tear Down
                </button>
                <button
                  className="secondary-action compact"
                  onClick={() => {
                    setTestDeployTeardownStatus("idle");
                    setTestDeployTeardownConfirmation("");
                  }}
                  type="button"
                >
                  Cancel
                </button>
              </div>
            ) : null}
          </section>
          {showTeardownActivity ? (
            <section className="confirmation-panel deployment-console-summary" aria-label="Infrastructure teardown console summary">
              <div className="section-heading">
                <div>
                  <h3>Teardown Console</h3>
                  <p>{infrastructureConsoleSummary}</p>
                  {teardownFailureDetail ? <p role="alert">{teardownFailureDetail}</p> : null}
                  {teardownRemainingResources.length ? <p>Remaining: {teardownRemainingResources.join(", ")}</p> : null}
                </div>
                <div className="section-actions">
                  <span>{activityStatus}</span>
                  {finalCleanupStatus === "verified_clean" && !teardownInProgress ? (
                    <button
                      className="secondary-action compact"
                      onClick={() => {
                        onBeginTestDeploymentTeardown();
                      }}
                      type="button"
                    >
                      Reconcile Cleanup
                    </button>
                  ) : null}
                  <button className="secondary-action compact" onClick={() => setInfrastructureConsoleOpen(true)} type="button">
                    <LaptopMinimalCheck aria-hidden="true" size={16} />
                    Open Console
                  </button>
                </div>
              </div>
            </section>
          ) : null}
          {!teardownRecoveryOnly ? renderLiveSketchChainLifecycle() : null}
          {!teardownRecoveryOnly ? <details className="advanced-settings-panel core-redeploy-panel">
            <summary>Advanced: Re-Deploy Core Infrastructure</summary>
            <div className="inline-warning">
              Re-deploying core rerolls homebase and proxies. SSH host keys, Team access, services, and channels may need to be reapplied.
            </div>
            <label>
              <span>Type {coreRecreatePhrase}</span>
              <input
                aria-label="Confirm core recreate phrase"
                onChange={(event) => setCoreRecreateConfirmation(event.target.value)}
                placeholder={coreRecreatePhrase}
                value={coreRecreateConfirmation}
              />
            </label>
            <button
              className="danger-action"
              disabled={!coreRecreateReady}
              onClick={() =>
                onRunTestDeployment({
                  recreateCore: true,
                  recreateConfirmation: coreRecreateConfirmation
                })
              }
              type="button"
            >
              Re-Deploy Core Infrastructure
            </button>
          </details> : null}
        </div>
      </section>
    );
    return (
      <section className="workflow-view" aria-label="Engagements">
        {activeEngagementTab === "overview" ? (
          <section className="operations-dashboard" aria-label="Engagement operations dashboard">
            <section className="guided-review" aria-label="Engagement status report">
              <div className="section-heading">
                <h3>Red team infrastructure status</h3>
                <div className="section-actions">
                  <span>{engagementOperationsStatus}</span>
                  <button
                    className="secondary-action compact"
                    disabled={!overviewMarkdown}
                    onClick={() => {
                      if (!navigator.clipboard || !overviewMarkdown) {
                        return;
                      }
                      void navigator.clipboard.writeText(overviewMarkdown).then(() => setOverviewMarkdownCopied(true));
                    }}
                    type="button"
                  >
                    Copy Markdown
                  </button>
                  <button
                    className="secondary-action compact"
                    disabled={!overviewMarkdown}
                    onClick={() => downloadTextFile(overviewMarkdownDownloadName, overviewMarkdown)}
                    type="button"
                  >
                    Download Markdown
                  </button>
                </div>
              </div>
              <div className="detail-grid test-deploy-grid">
                <div>
                  <span>Infrastructure lifecycle</span>
                  <strong className={`lifecycle-state lifecycle-${engagementOperations?.lifecycle?.state ?? "unknown"}`}>
                    {engagementOperations?.lifecycle?.label ?? "Unknown"}
                  </strong>
                </div>
                <div>
                  <span>Hosts</span>
                  <strong>{coreHostCountLabel(engagementOperations)}</strong>
                </div>
                <div>
                  <span>Sketch nodes</span>
                  <strong>{engagementOperations?.sketchInfrastructure.length ?? 0}</strong>
                </div>
                <div>
                  <span>Outbound channels</span>
                  <strong>{engagementOperations?.outboundChannels.length ?? 0}</strong>
                </div>
                <div>
                  <span>Last probe</span>
                  <strong>{formatOperationsTimestamp(engagementOperations?.healthSummary.lastCheckedAt)}</strong>
                </div>
                <div>
                  <span>Health</span>
                  <strong>{engagementOperations?.healthSummary.status ?? "unknown"}</strong>
                </div>
              </div>
              {overviewMarkdownCopied ? <p className="guardrail-hint">Markdown copied.</p> : null}
            </section>

            <section className="guided-review housekeeping-panel" aria-label="Housekeeping Items panel">
              <div className="section-heading">
                <h3>Housekeeping Items</h3>
                <button
                  className="secondary-action compact"
                  disabled={engagementOperationsStatus === "saving" || !selectedEngagementId}
                  onClick={onSaveHousekeepingItems}
                  type="button"
                >
                  {engagementOperationsStatus === "saving" ? "Saving" : "Save"}
                </button>
              </div>
              <textarea
                aria-label="Housekeeping Items"
                onChange={(event) => setHousekeepingItemsDraft(event.target.value)}
                placeholder="Operator notes, setup caveats, changes made during the engagement, or current operational context."
                rows={6}
                value={housekeepingItemsDraft}
              />
            </section>

            <section className="table-panel embedded operations-table core-infra-table" aria-label="Core infrastructure">
              <div className="section-heading table-section-heading">
                <h3>Core Infrastructure</h3>
                <span>{engagementOperations?.coreInfrastructure.length ?? 0} hosts</span>
              </div>
              <TableHeader columns={["Hostname", "Role", "Status", "Public IP", "Private IP", "Region", "Compartment", "Services", "Health"]} />
              {engagementOperations?.coreInfrastructure.length ? (
                engagementOperations.coreInfrastructure.map((host) => (
                  <div className="table-row" key={`ops-host-${host.hostname}`}>
                    <span>{operationValue(host.hostname, "Not Deployed")}</span>
                    <span>{operationValue(host.role, "N/A")}</span>
                    <StatusPill value={operationValue(host.lifecycleState ?? host.status, "unknown")} />
                    <code>{operationValue(host.publicIp, "Not Deployed")}</code>
                    <code>{operationValue(host.privateIp, "Not Deployed")}</code>
                    <span>{operationValue(host.region, "N/A")}</span>
                    <span>{operationValue(host.compartment, "N/A")}</span>
                    <span>{operationListValue(host.services, "N/A")}</span>
                    <HealthBadge health={host.health} />
                  </div>
                ))
              ) : (
                <OperationsEmptyState message="No deployed core infrastructure has been recorded for this engagement yet." />
              )}
            </section>

            <section className="table-panel embedded operations-table" aria-label="Sketch infrastructure">
              <div className="section-heading table-section-heading">
                <h3>Sketch Infrastructure</h3>
                <span>{engagementOperations?.sketchInfrastructure.length ?? 0} nodes</span>
              </div>
              <TableHeader columns={["Chain", "Role", "Status", "Hostname", "Public IP", "Provider", "Region", "Proxy"]} />
              {engagementOperations?.sketchInfrastructure.length ? (
                engagementOperations.sketchInfrastructure.map((node) => (
                  <div className="table-row" key={`ops-sketch-${node.chainId}-${node.role}-${node.hostname}`}>
                    <span>
                      <strong>{operationValue(node.chainId, "N/A")}</strong>
                    </span>
                    <span>{operationValue(node.role, "N/A")}</span>
                    <span>
                      <StatusPill value={operationValue(node.status, "Not Ready")} />
                      {node.burned ? <small>Burned{node.burnedNote ? ` · ${node.burnedNote}` : ""}</small> : null}
                    </span>
                    <span>{operationValue(node.hostname, "Not Deployed")}</span>
                    <code>{operationValue(node.publicIp, "Not Deployed")}</code>
                    <span>{operationValue(node.provider, "N/A")}</span>
                    <span>{operationValue(node.region, "N/A")}</span>
                    <span>{operationValue(node.proxy, "Not Deployed")}</span>
                  </div>
                ))
              ) : (
                <OperationsEmptyState message="No sketch middle or edge nodes are configured yet." />
              )}
            </section>

            {((engagementOperations?.providerFindings?.length ?? 0) || providerOrphanRecoveryAction.message) ? (
              <section className="table-panel embedded operations-table" aria-label="Provider tracking findings">
                <div className="section-heading table-section-heading">
                  <div>
                    <h3>Provider Tracking</h3>
                    <p>Provider-visible RTI resources that are not yet tied to durable Barragan records.</p>
                  </div>
                  <div className="section-actions">
                    <span>{engagementOperations?.providerFindings?.length ?? 0} findings</span>
                    {providerOrphanRecoveryAction.job ? (
                      <button className="secondary-action compact" onClick={() => onOpenLifecycleConsole("provider")} type="button">
                        <ListChecks aria-hidden="true" size={14} />
                        Log
                      </button>
                    ) : null}
                  </div>
                </div>
                {providerOrphanRecoveryAction.message ? (
                  <div className="inline-warning" role="status">
                    {providerOrphanRecoveryAction.message}
                    {providerOrphanRecoveryAction.job ? ` Job ${providerOrphanRecoveryAction.job.id}.` : ""}
                  </div>
                ) : null}
                {engagementOperations?.providerFindings?.length ? (
                  <>
                    <TableHeader columns={["Provider", "Resource", "State", "Region", "Reason", "Actions"]} />
                    {(engagementOperations.providerFindings ?? []).map((candidate) => {
                      const allowedActions = new Set(candidate.actions ?? []);
                      const confirmationActive =
                        providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId &&
                        Boolean(providerOrphanRecoveryAction.confirmationToken);
                      const confirmationMatches =
                        confirmationActive &&
                        providerOrphanRecoveryAction.confirmationValue === providerOrphanRecoveryAction.confirmationToken;
                      return (
                        <div className="table-row" key={`engagement-provider-finding-${candidate.candidateId}`}>
                          <span>{candidate.provider}</span>
                          <span>{candidate.name || candidate.resourceId}</span>
                          <StatusPill value={candidate.lifecycleState} />
                          <span>{candidate.region || "N/A"}</span>
                          <span>{candidate.reason}</span>
                          <span className="section-actions compact-actions">
                            {allowedActions.has("track") ? (
                              <button
                                className="secondary-action compact"
                                disabled={providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId}
                                onClick={() => onRecoverProviderOrphan(candidate, "track")}
                                type="button"
                              >
                                Track
                              </button>
                            ) : null}
                            {allowedActions.has("mark_destroyed") ? (
                              <button
                                className="secondary-action compact"
                                disabled={providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId}
                                onClick={() => onRecoverProviderOrphan(candidate, "mark_destroyed")}
                                type="button"
                              >
                                Record Destroyed Note
                              </button>
                            ) : null}
                            {allowedActions.has("tear_down") ? (
                              <button
                                className="danger-action compact"
                                disabled={providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId}
                                onClick={() => onRecoverProviderOrphan(candidate, "tear_down")}
                                type="button"
                              >
                                Teardown Plan
                              </button>
                            ) : null}
                            {confirmationActive ? (
                              <span className="provider-recovery-confirmation">
                                <label>
                                  <span>Type {providerOrphanRecoveryAction.confirmationToken}</span>
                                  <input
                                    aria-label={`Live teardown confirmation for ${candidate.name || candidate.resourceId}`}
                                    onChange={(event) =>
                                      onSetProviderOrphanTeardownConfirmation(candidate.candidateId, event.target.value)
                                    }
                                    type="text"
                                    value={providerOrphanRecoveryAction.confirmationValue}
                                  />
                                </label>
                                <button
                                  className="danger-action compact"
                                  disabled={(providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId) || !confirmationMatches}
                                  onClick={() =>
                                    onRecoverProviderOrphan(candidate, "tear_down", {
                                      mutation: true,
                                      confirmation: providerOrphanRecoveryAction.confirmationValue
                                    })
                                  }
                                  type="button"
                                >
                                  Confirm Teardown
                                </button>
                              </span>
                            ) : null}
                          </span>
                        </div>
                      );
                    })}
                  </>
                ) : null}
              </section>
            ) : null}

            <section className="table-panel embedded operations-table" aria-label="Outbound Channels">
              <div className="section-heading table-section-heading">
                <h3>Outbound Channels</h3>
                <span>operator route map</span>
              </div>
              <TableHeader columns={["Proxy", "Middle", "Edge", "Port", "Region", "Provider", "Domain", "Purpose", "Status"]} />
              {engagementOperations?.outboundChannels.length ? (
                engagementOperations.outboundChannels.map((channel) => (
                  <div className="table-row" key={`ops-outbound-${outboundChannelActionId(channel)}`}>
                    <span>{operationValue(channel.proxy, "Not Deployed")}</span>
                    <span>{operationValue(channel.middle, "Not Deployed")}</span>
                    <span>{operationValue(channel.edge, "Not Deployed")}</span>
                    <span>{operationValue(channel.port, "N/A")}</span>
                    <span>{operationValue(channel.region, "N/A")}</span>
                    <span>{operationValue(channel.provider, "N/A")}</span>
                    <span>{operationValue(channel.domain, "N/A")}</span>
                    <span>{operationValue(channel.purpose, "N/A")}</span>
                    <StatusPill value={operationValue(channel.status, "Not Ready")} />
                  </div>
                ))
              ) : (
                <OperationsEmptyState message="No outbound sketch channels are configured yet. Outbound Channels will show proxy, middle, edge, port, and domain mappings once configured." />
              )}
            </section>

            <section className="table-panel embedded operations-table" aria-label="Inbound Channels">
              <div className="section-heading table-section-heading">
                <h3>Inbound Channels</h3>
                <span>{engagementOperations?.inboundChannels.length ?? 0} channels</span>
              </div>
              <TableHeader columns={["Domain", "Protocol", "External Port", "Edge", "Middle", "Proxy", "Terminates On", "Service", "Internal Port", "Purpose", "Status"]} />
              {engagementOperations?.inboundChannels.length ? (
                engagementOperations.inboundChannels.map((channel) => (
                  <div className="table-row" key={`ops-inbound-${channel.channelId}`}>
                    <span>{operationValue(channel.domain, "N/A")}</span>
                    <span>{operationValue(channel.protocol, "N/A")}</span>
                    <span>{operationValue(channel.externalPort, "N/A")}</span>
                    <span>{operationValue(channel.edge, "Not Deployed")}</span>
                    <span>{operationValue(channel.middle, "Not Deployed")}</span>
                    <span>{operationValue(channel.proxy, "Not Deployed")}</span>
                    <span>{operationValue(channel.terminatesOn, "Not Deployed")}</span>
                    <span>{operationValue(channel.service, "N/A")}</span>
                    <span>{operationValue(channel.internalPort, "N/A")}</span>
                    <span>{operationValue(channel.purpose, "N/A")}</span>
                    <StatusPill value={operationValue(channel.status, "Not Ready")} />
                  </div>
                ))
              ) : (
                <OperationsEmptyState message="No inbound channels are configured yet. Inbound Channels will show external-to-internal port mappings and the service where traffic terminates." />
              )}
            </section>

            <section className="ssh-config-panel" aria-label="SSH config stanza">
              <div className="section-heading">
                <h3>SSH config</h3>
                <div className="section-actions">
                  <button
                    className="secondary-action compact"
                    disabled={!sshConfigStanza}
                    onClick={() => {
                      void navigator.clipboard.writeText(sshConfigStanza).then(() => setSshConfigCopied(true));
                    }}
                    type="button"
                  >
                    Copy
                  </button>
                  <a className={`secondary-action compact link-action${sshConfigStanza ? "" : " disabled"}`} download={sshConfigDownloadName} href={sshConfigDownloadHref || undefined}>
                    Download
                  </a>
                </div>
              </div>
              <pre>{sshConfigStanza || "SSH config will appear after deployment connection details are recorded."}</pre>
              <p>{sshConfigCopied ? "Copied." : "Use this as an include file under ~/.ssh/configs/."}</p>
            </section>

            <details className="ssh-config-panel" aria-label="Advanced sketch SSH keys">
              <summary>Advanced sketch SSH keys</summary>
              <div className="section-heading">
                <div>
                  <h3>Sketch SSH key</h3>
                  <p>Engagement-scoped key used for sketch middle and edge nodes.</p>
                </div>
                <span>{sketchSshKeyStatus}</span>
              </div>
              {sketchSshKey ? (
                <div className="detail-grid test-deploy-grid">
                  <div>
                    <span>Private key</span>
                    <strong>{sketchSshKey.privateKeyName}</strong>
                  </div>
                  <div>
                    <span>Public key</span>
                    <strong>{sketchSshKey.publicKeyName}</strong>
                  </div>
                  <div>
                    <span>Fingerprint</span>
                    <strong>{sketchSshKey.fingerprint}</strong>
                  </div>
                </div>
              ) : (
                <p>No sketch SSH key has been generated for this engagement.</p>
              )}
              {sketchSshKey?.retiredKeys?.length ? (
                <div className="table-panel embedded operations-table" aria-label="Retired sketch SSH keys">
                  <TableHeader columns={["Fingerprint", "Status", "Reason", "Retired at"]} />
                  {sketchSshKey.retiredKeys.map((retiredKey, index) => (
                    <div className="table-row" key={`retired-sketch-key-${retiredKey.fingerprint || index}`}>
                      <span>{retiredKey.fingerprint || "Not Recorded"}</span>
                      <StatusPill value={retiredKey.status || "retired"} />
                      <span>{retiredKey.reason || "rotated"}</span>
                      <span>{retiredKey.retiredAt || "Not Recorded"}</span>
                    </div>
                  ))}
                </div>
              ) : null}
              <div className="section-actions">
                <button
                  className="secondary-action compact"
                  disabled={!selectedEngagementId || sketchSshKeyStatus === "saving"}
                  onClick={onGenerateSketchSshKey}
                  type="button"
                >
                  {sketchSshKey ? "Ensure Key Exists" : "Generate Key"}
                </button>
                <button
                  className="secondary-action compact"
                  disabled={!sketchSshKey || sketchSshKeyStatus === "loading"}
                  onClick={onDownloadSketchSshKey}
                  type="button"
                >
                  Download Key Files
                </button>
              </div>
              <p>Key material is only retrieved for this explicit download action and is not rendered in the page.</p>
              <div className="table-panel embedded" aria-label="Sketch SSH config stanzas">
                <div className="section-heading">
                  <div>
                    <h4>Sketch SSH stanzas</h4>
                    <p>Use these from your workstation with the core SSH config above. Edges are reached through the selected proxy and matching middle.</p>
                  </div>
                  <button
                    className="secondary-action compact"
                    disabled={!sketchSshConfigStanza}
                    onClick={() => {
                      void navigator.clipboard.writeText(sketchSshConfigStanza).then(() => setSshConfigCopied(true));
                    }}
                    type="button"
                  >
                    Copy
                  </button>
                </div>
                <pre>{sketchSshConfigStanza || "Sketch SSH stanzas will appear after sketch middle and edge nodes are recorded."}</pre>
              </div>
              <div className="table-panel embedded" aria-label="Sketch SSH key rotation">
                <div className="section-heading">
                  <div>
                    <h4>Rotate sketch key</h4>
                    <p>Preview the impact before generating a new engagement key.</p>
                  </div>
                  <StatusPill value={sketchSshKeyRotationAction.preview?.status ?? sketchSshKeyRotationAction.status} />
                </div>
                <div className="section-actions">
                  <button
                    className="secondary-action compact"
                    disabled={!selectedEngagementId || sketchSshKeyRotationAction.status === "running"}
                    onClick={onPreviewSketchSshKeyRotation}
                    type="button"
                  >
                    Preview Rotation
                  </button>
                </div>
                {sketchSshKeyRotationAction.preview ? (
                  <>
                    <div className="detail-grid test-deploy-grid">
                      <div>
                        <span>Current fingerprint</span>
                        <strong>{sketchSshKeyRotationAction.preview.currentKey?.fingerprint ?? "No current key"}</strong>
                      </div>
                      <div>
                        <span>Requires repair</span>
                        <strong>{sketchSshKeyRotationAction.preview.requiresRepair ? "Yes" : "No"}</strong>
                      </div>
                      <div>
                        <span>Confirmation token</span>
                        <strong>{sketchSshKeyRotationAction.preview.confirmation}</strong>
                      </div>
                      <div>
                        <span>Direct sketch access</span>
                        <strong>{String(sketchSshKeyRotationAction.preview.opsecBoundary.directSketchAccess)}</strong>
                      </div>
                      <div>
                        <span>Middle access</span>
                        <strong>{String(sketchSshKeyRotationAction.preview.opsecBoundary.middleAccess ?? "proxy jump only")}</strong>
                      </div>
                      <div>
                        <span>Edge access</span>
                        <strong>{String(sketchSshKeyRotationAction.preview.opsecBoundary.edgeAccess ?? "proxy to middle jump only")}</strong>
                      </div>
                    </div>
                    {sketchSshKeyRotationAction.preview.affectedChains.length ? (
                      <div className="table-panel embedded operations-table" aria-label="Rotation affected sketch chains">
                        <TableHeader columns={["Chain", "Proxy", "Status", "Required action"]} />
                        {sketchSshKeyRotationAction.preview.affectedChains.map((chain, index) => (
                          <div className="table-row" key={`rotation-chain-${String(chain.chainId ?? index)}`}>
                            <span>{String(chain.chainId ?? "N/A")}</span>
                            <span>{String(chain.assignedProxy ?? "N/A")}</span>
                            <StatusPill value={String(chain.status ?? "Not Ready")} />
                            <span>{String(chain.requiredAction ?? "reprovision_or_opsec_safe_repair")}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p>No deployed sketch chains require repair for this rotation.</p>
                    )}
                    <ul className="status-list">
                      {sketchSshKeyRotationAction.preview.steps.map((step, index) => (
                        <li key={`rotation-step-${String(step.id ?? index)}`}>
                          <strong>{String(step.status ?? "pending")}</strong>
                          <span>{String(step.detail ?? step.id ?? "Rotation step")}</span>
                        </li>
                      ))}
                    </ul>
                    <label>
                      Confirmation
                      <input
                        onChange={(event) =>
                          setSketchSshKeyRotationAction((current) => ({
                            ...current,
                            confirmation: event.target.value
                          }))
                        }
                        placeholder={sketchSshKeyRotationAction.preview.confirmation}
                        value={sketchSshKeyRotationAction.confirmation}
                      />
                    </label>
                    <div className="section-actions">
                      <button
                        className="danger-action compact"
                        disabled={
                          sketchSshKeyRotationAction.status === "running" ||
                          sketchSshKeyRotationAction.preview.requiresRepair ||
                          sketchSshKeyRotationAction.confirmation !== sketchSshKeyRotationAction.preview.confirmation
                        }
                        onClick={onRotateSketchSshKey}
                        type="button"
                      >
                        Rotate Sketch Key
                      </button>
                    </div>
                  </>
                ) : (
                  <p>Preview rotation before changing the engagement sketch key.</p>
                )}
                {sketchSshKeyRotationAction.previousFingerprint ? (
                  <p>Previous fingerprint: {sketchSshKeyRotationAction.previousFingerprint}</p>
                ) : null}
                {sketchSshKeyRotationAction.message ? <p>{sketchSshKeyRotationAction.message}</p> : null}
              </div>
              <div className="table-panel embedded" aria-label="Sketch SSH key removal">
                <div className="section-heading">
                  <div>
                    <h4>Remove sketch key</h4>
                    <p>Delete encrypted key material only after engagement infrastructure is torn down.</p>
                  </div>
                  <StatusPill value={sketchSshKeyRemovalAction.preview?.status ?? sketchSshKeyRemovalAction.status} />
                </div>
                <div className="section-actions">
                  <button
                    className="secondary-action compact"
                    disabled={!selectedEngagementId || sketchSshKeyRemovalAction.status === "running"}
                    onClick={onPreviewSketchSshKeyRemoval}
                    type="button"
                  >
                    Preview Removal
                  </button>
                </div>
                {sketchSshKeyRemovalAction.preview ? (
                  <>
                    <div className="detail-grid test-deploy-grid">
                      <div>
                        <span>Current fingerprint</span>
                        <strong>{sketchSshKeyRemovalAction.preview.currentKey?.fingerprint ?? "No current key"}</strong>
                      </div>
                      <div>
                        <span>Requires teardown</span>
                        <strong>{sketchSshKeyRemovalAction.preview.requiresTeardown ? "Yes" : "No"}</strong>
                      </div>
                      <div>
                        <span>Confirmation token</span>
                        <strong>{sketchSshKeyRemovalAction.preview.confirmation}</strong>
                      </div>
                      <div>
                        <span>Direct sketch access</span>
                        <strong>{String(sketchSshKeyRemovalAction.preview.opsecBoundary.directSketchAccess)}</strong>
                      </div>
                      <div>
                        <span>Middle access</span>
                        <strong>{String(sketchSshKeyRemovalAction.preview.opsecBoundary.middleAccess ?? "proxy jump only")}</strong>
                      </div>
                      <div>
                        <span>Edge access</span>
                        <strong>{String(sketchSshKeyRemovalAction.preview.opsecBoundary.edgeAccess ?? "proxy to middle jump only")}</strong>
                      </div>
                    </div>
                    {sketchSshKeyRemovalAction.preview.blockers.length ? (
                      <div className="table-panel embedded operations-table" aria-label="Removal blockers">
                        <TableHeader columns={["Type", "Chain", "Status", "Required action"]} />
                        {sketchSshKeyRemovalAction.preview.blockers.map((blocker, index) => (
                          <div className="table-row" key={`removal-blocker-${String(blocker.kind ?? index)}`}>
                            <span>{String(blocker.kind ?? "blocker")}</span>
                            <span>{String(blocker.chainId ?? "N/A")}</span>
                            <StatusPill value={String(blocker.status ?? "Blocked")} />
                            <span>{String(blocker.requiredAction ?? blocker.detail ?? "tear_down_infrastructure_first")}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p>No recorded infrastructure blocks key removal.</p>
                    )}
                    <ul className="status-list">
                      {sketchSshKeyRemovalAction.preview.steps.map((step, index) => (
                        <li key={`removal-step-${String(step.id ?? index)}`}>
                          <strong>{String(step.status ?? "pending")}</strong>
                          <span>{String(step.detail ?? step.id ?? "Removal step")}</span>
                        </li>
                      ))}
                    </ul>
                    <label>
                      Confirmation
                      <input
                        onChange={(event) =>
                          setSketchSshKeyRemovalAction((current) => ({
                            ...current,
                            confirmation: event.target.value
                          }))
                        }
                        placeholder={sketchSshKeyRemovalAction.preview.confirmation}
                        value={sketchSshKeyRemovalAction.confirmation}
                      />
                    </label>
                    <div className="section-actions">
                      <button
                        className="danger-action compact"
                        disabled={
                          sketchSshKeyRemovalAction.status === "running" ||
                          sketchSshKeyRemovalAction.preview.requiresTeardown ||
                          sketchSshKeyRemovalAction.confirmation !== sketchSshKeyRemovalAction.preview.confirmation
                        }
                        onClick={onRemoveSketchSshKey}
                        type="button"
                      >
                        Remove Sketch Key
                      </button>
                    </div>
                  </>
                ) : (
                  <p>Preview removal before deleting encrypted sketch key material.</p>
                )}
                {sketchSshKeyRemovalAction.removedFingerprint ? (
                  <p>Removed fingerprint: {sketchSshKeyRemovalAction.removedFingerprint}</p>
                ) : null}
                {sketchSshKeyRemovalAction.message ? <p>{sketchSshKeyRemovalAction.message}</p> : null}
              </div>
            </details>

            <EngagementDomainsPanel engagementId={selectedEngagementId} />
          </section>
        ) : null}

        {activeEngagementTab === "domains" ? (
          <EngagementDnsPage engagementId={selectedEngagementId} />
        ) : null}

        {activeEngagementTab === "certificates" ? (
          <CertificateManagerPage engagementId={selectedEngagementId} />
        ) : null}

        {activeEngagementTab === "infrastructure" ? (
        <div className="guided-workflow" aria-label="Guided deployment workflow">
          {infrastructureWorkflow === "loading" ? (
            <section className="workflow-panel" role="status">
              <h3>Loading infrastructure state</h3>
              <p>{engagementOperations?.lifecycle?.state === "deploying"
                ? "Barragan is loading the current core deployment job before showing progress."
                : "Barragan is waiting for authoritative Operations data before enabling infrastructure actions."}</p>
            </section>
          ) : infrastructureWorkflow === "unavailable" ? (
            <section className="workflow-panel" role="alert">
              <h3>Infrastructure state unavailable</h3>
              <p>Barragan could not load authoritative Operations data. Infrastructure actions remain disabled.</p>
            </section>
          ) : infrastructureWorkflow === "historical" ? (
            <section className="workflow-step-group" aria-label="Destroyed infrastructure">
              <section className="workflow-panel workflow-section-heading">
                <div>
                  <h3>Infrastructure Destroyed</h3>
                  <p>Verified cleanup confirms the known owned infrastructure is gone. Retained deployment records are historical.</p>
                </div>
              </section>
              {renderCurrentCoreInfrastructure(true)}
            </section>
          ) : infrastructureWorkflow === "blocked" ? (
            <section className="workflow-panel" role="alert">
              <h3>Cleanup recovery unavailable</h3>
              <p>{teardownRequestUnconfirmed ? "Teardown could not be confirmed. Review Operations before trying again." : engagementOperations?.teardownSelection?.state === "ambiguous" ? "Multiple teardown records match this deployment. Review Operations history before changing infrastructure." : "Barragan could not identify the exact teardown parent for this deployment. Review Operations history before changing infrastructure."}</p>
            </section>
          ) : infrastructureWorkflow === "deploying" ? (
            <section className="workflow-step-group" aria-label="Infrastructure deployment in progress">
              <section className="workflow-panel workflow-section-heading">
                <div>
                  <h3>Deploying Infrastructure</h3>
                  <p>{infrastructureConsoleSummary}</p>
                </div>
                <button className="secondary-action compact" onClick={() => setInfrastructureConsoleOpen(true)} type="button">Open Console</button>
              </section>
              {renderCurrentCoreInfrastructure()}
            </section>
          ) : infrastructureWorkflow === "teardown_recovery" ? (
            renderRunningInfrastructureWorkflow(true)
          ) : infrastructureWorkflow === "running" ? (
            renderRunningInfrastructureWorkflow()
          ) : (
          <>
          <ol className="workflow-steps" aria-label="Workflow steps">
            <li className="deployment-step done">
              <span className="step-index">Step 1</span>
              <div>
                <strong>Select template and customizations</strong>
                <span>Choose the active engagement infrastructure shape.</span>
              </div>
              <span className="step-status">DONE</span>
            </li>
            <li className={`deployment-step ${corePlanReady ? "done" : corePlan?.status === "failed" ? "failed" : corePlanStatus === "preparing" ? "wip" : "pending"}`}>
              <span className="step-index">Step 2</span>
              <div>
                <strong>Review deployment</strong>
                <span>Prepare the deployment plan and verify safety checks.</span>
              </div>
              <span className="step-status">{corePlanReady ? "DONE" : corePlan?.status === "failed" ? "FAILED" : corePlanStatus === "preparing" ? "WIP" : corePlan?.status === "outdated" || corePlan?.status === "invalidated" ? "OUTDATED" : "PENDING"}</span>
            </li>
            <li className={`deployment-step ${coreApplyStepState}`}>
              <span className="step-index">Step 3</span>
              <div>
                <strong>Deploy and watch progress</strong>
                <span>Deploy to the selected compartment, then hold for operator inspection.</span>
              </div>
              <span className="step-status">{coreApplyStepState.toUpperCase()}</span>
            </li>
          </ol>

          <section className="workflow-step-group" aria-label="Step 1 workflow group">
            <section className="workflow-panel workflow-section-heading" aria-label="Step 1 Select template and customizations">
              <div>
                <h3>1. Select Template And Customizations</h3>
                <p>Choose the standard RTI shape and sketch chains for this engagement.</p>
              </div>
            </section>

            <div className="workflow-step-body">
              <section className="guided-form infrastructure-form" aria-label="Infrastructure customizations">
            <label>
              <span>Template</span>
              <select
                aria-label="Infrastructure template"
                disabled={providerCatalogStatus !== "ready"}
                onChange={(event) => {
                  const nextTemplateId = event.target.value;
                  const allowedProxies = proxyOptionsForTemplate(nextTemplateId);
                  setSelectedInfrastructureTemplateId(nextTemplateId);
                  if (nextTemplateId === "small-dev-infra") {
                    setGuidedElkEnabled(false);
                  }
                  setSketchIntent((current) => {
                    const kept = current.filter((chain) => allowedProxies.includes(chain.assignedProxy));
                    return kept.length ? kept : allowedProxies.map((proxy) => defaultSketchChain(proxy));
                  });
                }}
                value={selectedInfrastructureTemplateId}
              >
                {data.templates.map((template) => (
                  <option key={template.id} value={template.id}>{template.name}: {template.description}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Homebases</span>
              <input aria-label="Homebase count" readOnly value="1" />
            </label>
            <label>
              <span>Proxies</span>
              <input aria-label="Proxy count" readOnly value={String(activeInfrastructureProxyOptions.length)} />
            </label>
            <label className="checkbox-row">
              <input
                aria-label="Include ELK node"
                checked={guidedDeploymentInput.elkEnabled}
                disabled={selectedInfrastructureTemplateId === "small-dev-infra"}
                onChange={(event) => setGuidedElkEnabled(event.target.checked)}
                type="checkbox"
              />
              <span>{selectedInfrastructureTemplateId === "small-dev-infra" ? "ELK is unavailable on Small Dev Infra" : "Include one private ELK node"}</span>
            </label>
            <label>
              <span>Target compartment</span>
              <select
                aria-label="Target compartment"
                disabled={!testDeployReadiness?.availableTargets?.length}
                onChange={(event) => {
                  setSelectedDeploymentTargetName(event.target.value);
                  setTestDeployConfirmation("");
                }}
                value={selectedDeploymentTarget?.name ?? "barragan-testing"}
              >
                {(testDeployReadiness?.availableTargets ?? [testDeployReadiness?.target].filter(Boolean)).map((target) => (
                  <option key={target!.compartmentId} value={target!.name}>
                    {target!.name}{target!.classification === "production" ? " · production" : " · testing"}
                  </option>
                ))}
              </select>
            </label>
            <details className="advanced-settings-panel">
              <summary>Advanced deployment safety settings</summary>
              <label>
                <span>SSH allowed from</span>
                <textarea
                  aria-label="SSH allowed CIDRs"
                  onChange={(event) => setTestDeploySshSourceCidrs(event.target.value)}
                  placeholder="160.34.86.0/23"
                  rows={5}
                  value={testDeploySshSourceCidrs}
                />
              </label>
              <p className="guardrail-hint">Default trusted CIDR blocks are applied automatically. Modify this only when operator SSH access needs a different source range.</p>
            </details>
            <section className="table-panel embedded sketch-chain-editor" aria-label="Sketch chains by proxy">
              <div className="section-heading table-section-heading">
                <h3>Sketch chains by proxy</h3>
                <span>{guidedDeploymentInput.sketchChains.length} chains · catalogs {providerCatalogStatus}</span>
              </div>
              {providerCatalogStatus === "error" ? (
                <div className="inline-warning" role="alert">
                  Provider catalogs could not be loaded. Infrastructure changes remain disabled until authoritative provider data is available.
                  <div className="section-actions">
                    <button className="secondary-action compact" onClick={() => void onEnsureProviderCatalogs()} type="button">
                      Retry Provider Catalog
                    </button>
                  </div>
                </div>
              ) : null}
              {providerCatalogWarnings.length ? (
                <div className="inline-warning" role="status">
                  {providerCatalogWarnings.join(" ")}
                </div>
              ) : null}
              {activeInfrastructureProxyOptions.map((proxy) => {
                const proxyChains = sketchChainsForEditor.filter((chain) => chain.assignedProxy === proxy);
                return (
                  <section className="table-panel embedded proxy-sketch-panel" aria-label={`${proxy} sketch chains`} key={`sketch-editor-${proxy}`}>
                    <div className="section-heading table-section-heading">
                      <h3>{proxy}</h3>
                      <div className="section-actions">
                        <span>{proxyChains.length} chain{proxyChains.length === 1 ? "" : "s"}</span>
                        <button className="secondary-action compact" disabled={providerCatalogStatus !== "ready"} onClick={() => addSketchChain(proxy)} type="button">
                          Add Chain
                        </button>
                      </div>
                    </div>
                    {proxyChains.map((chain) => {
                      const chainIndex = sketchIntent[chain.sourceIndex] ? chain.sourceIndex : 0;
                      return (
                        <div className="workflow-panel sketch-chain-card" key={chain.id}>
                          <div className="section-heading">
                            <div>
                              <h3>{chain.id}</h3>
                              <p>{chain.assignedProxy} owns this middle/edge route.</p>
                            </div>
                            <button
                              className="secondary-action compact danger"
                              disabled={providerCatalogStatus !== "ready" || sketchIntent.length <= 1}
                              onClick={() => removeSketchChain(chainIndex)}
                              type="button"
                            >
                              Remove
                            </button>
                          </div>
                          <label>
                            <span>Middle provider</span>
                            <select
                              aria-label={`${chain.id} middle provider`}
                              disabled={providerCatalogStatus !== "ready"}
                              onChange={(event) => {
                                const defaults = providerDefaults(providerCatalogs, event.target.value);
                                updateSketchChain(chainIndex, {
                                  middleProvider: event.target.value,
                                  middleRegion: defaults.region,
                                  middleSize: defaults.size
                                });
                              }}
                              value={chain.middleProvider}
                            >
                              {sketchProviderOptions.map((provider) => (
                                <option key={provider} value={provider}>{provider}</option>
                              ))}
                            </select>
                          </label>
                          <label>
                            <span>Middle region</span>
                            <select
                              aria-label={`${chain.id} middle region`}
                              disabled={providerCatalogStatus !== "ready"}
                              onChange={(event) =>
                                updateSketchChain(chainIndex, {
                                  middleRegion: event.target.value,
                                  middleSize: sizeForRegion(providerCatalogs, chain.middleProvider, event.target.value, chain.middleSize)
                                })
                              }
                              value={chain.middleRegion}
                            >
                              {regionOptions(providerCatalogs, chain.middleProvider, chain.middleRegion).map((region) => (
                                <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>
                              ))}
                            </select>
                          </label>
                          <label>
                            <span>Default edge provider</span>
                            <select
                              aria-label={`${chain.id} edge provider`}
                              disabled={providerCatalogStatus !== "ready"}
                              onChange={(event) => {
                                const defaults = providerDefaults(providerCatalogs, event.target.value);
                                const edges = chain.edges.map((edge) => ({
                                  ...edge,
                                  provider: event.target.value,
                                  region: defaults.region,
                                  size: chain.edges.length === 1
                                    ? sizeForRegion(providerCatalogs, event.target.value, defaults.region, edge.size)
                                    : defaults.size
                                }));
                                updateSketchChain(chainIndex, { edgeProvider: event.target.value, edgeRegion: defaults.region, edgeSize: edges[0].size, edges });
                              }}
                              value={chain.edgeProvider}
                            >
                              {sketchProviderOptions.map((provider) => <option key={provider} value={provider}>{provider}</option>)}
                            </select>
                          </label>
                          <label>
                            <span>Edge nodes</span>
                            <input
                              aria-label={`${chain.id} edge nodes`}
                              disabled={providerCatalogStatus !== "ready"}
                              max={10}
                              min={1}
                              onChange={(event) =>
                                updateSketchChain(chainIndex, resizeEdgeIntents(chain, Math.max(1, Math.min(10, Number.parseInt(event.target.value || "1", 10) || 1))))
                              }
                              type="number"
                              value={chain.edgeCount}
                            />
                          </label>
                          <label>
                            <span>Default edge region</span>
                            <select
                              aria-label={`${chain.id} default edge region`}
                              disabled={providerCatalogStatus !== "ready"}
                              onChange={(event) => {
                                const size = sizeForRegion(providerCatalogs, chain.edgeProvider, event.target.value, chain.edgeSize);
                                const edges = chain.edges.map((edge) => ({ ...edge, provider: chain.edgeProvider, region: event.target.value, size }));
                                updateSketchChain(chainIndex, { edgeRegion: event.target.value, edgeSize: size, edges });
                              }}
                              value={chain.edgeRegion}
                            >
                              {regionOptions(providerCatalogs, chain.edgeProvider, chain.edgeRegion).map((region) => (
                                <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>
                              ))}
                            </select>
                          </label>
                          {chain.edges.length > 1 ? (
                            <div className="wide-field" aria-label={`${chain.id} edge rows`}>
                              <span>Individual edge placement</span>
                              <p>Each edge may use its own provider, region, and size. The default controls reset every edge row.</p>
                              {chain.edges.map((edge, edgeIndex) => (
                                <div className="form-grid" key={edge.id}>
                                  <strong>Edge {String(edgeIndex + 1).padStart(2, "0")}</strong>
                                  <label><span>Provider</span><select aria-label={`${chain.id} edge ${String(edgeIndex + 1).padStart(2, "0")} provider`} disabled={providerCatalogStatus !== "ready"} value={edge.provider} onChange={(event) => { const defaults = providerDefaults(providerCatalogs, event.target.value); updateSketchChain(chainIndex, replaceEdgeIntent(chain, edgeIndex, { provider: event.target.value, region: defaults.region, size: defaults.size })); }}>{sketchProviderOptions.map((provider) => <option key={provider} value={provider}>{provider}</option>)}</select></label>
                                  <label><span>Region</span><select aria-label={`${chain.id} edge ${String(edgeIndex + 1).padStart(2, "0")} region`} disabled={providerCatalogStatus !== "ready"} value={edge.region} onChange={(event) => updateSketchChain(chainIndex, replaceEdgeIntent(chain, edgeIndex, { provider: edge.provider, region: event.target.value, size: sizeForRegion(providerCatalogs, edge.provider, event.target.value, edge.size) }))}>{regionOptions(providerCatalogs, edge.provider, edge.region).map((region) => <option disabled={!region.available} key={region.id} value={region.id}>{region.label}</option>)}</select></label>
                                  <label><span>Size/shape</span><select aria-label={`${chain.id} edge ${String(edgeIndex + 1).padStart(2, "0")} size`} disabled={providerCatalogStatus !== "ready"} value={edge.size} onChange={(event) => updateSketchChain(chainIndex, replaceEdgeIntent(chain, edgeIndex, { size: event.target.value }))}>{sizeOptions(providerCatalogs, edge.provider, edge.region, edge.size).map((size) => <option disabled={!size.available} key={size.id} value={size.id}>{sizeLabel(size)}</option>)}</select></label>
                                </div>
                              ))}
                            </div>
                          ) : null}
                          <details>
                            <summary>Advanced sketch settings</summary>
                            <label>
                              <span>Middle size/shape</span>
                              <select
                                aria-label={`${chain.id} middle size`}
                                disabled={providerCatalogStatus !== "ready"}
                                onChange={(event) => updateSketchChain(chainIndex, { middleSize: event.target.value })}
                                value={chain.middleSize}
                              >
                                {sizeOptions(providerCatalogs, chain.middleProvider, chain.middleRegion, chain.middleSize).map((size) => (
                                  <option disabled={!size.available} key={size.id} value={size.id}>{sizeLabel(size)}</option>
                                ))}
                              </select>
                            </label>
                            {chain.edges.length === 1 ? (
                              <label>
                                <span>Edge size/shape</span>
                                <select
                                  aria-label={`${chain.id} edge size`}
                                  disabled={providerCatalogStatus !== "ready"}
                                  onChange={(event) =>
                                    updateSketchChain(chainIndex, replaceEdgeIntent(chain, 0, { size: event.target.value }))
                                  }
                                  value={chain.edges[0].size}
                                >
                                  {sizeOptions(providerCatalogs, chain.edges[0].provider, chain.edges[0].region, chain.edges[0].size).map((size) => (
                                    <option disabled={!size.available} key={size.id} value={size.id}>{sizeLabel(size)}</option>
                                  ))}
                                </select>
                              </label>
                            ) : null}
                          </details>
                        </div>
                      );
                    })}
                  </section>
                );
              })}
            </section>
              </section>
            </div>
          </section>

          <section className="workflow-step-group" aria-label="Step 2 workflow group">
            <section className="workflow-panel workflow-section-heading" aria-label="Step 2 Review deployment">
              <div>
                <h3>2. Review Infrastructure Plan</h3>
                <p>Review the exact core Terraform changes and the validated post-core rollout before deployment.</p>
              </div>
              <div className="workflow-actions">
                <button
                  className="primary-action"
                  disabled={providerCatalogStatus !== "ready" || !selectedEngagementId || !sshSourceCidrsValid || corePlanStatus === "preparing" || corePlanStatus === "applying"}
                  onClick={onCompileSelectedRevision}
                  type="button"
                >
                  {corePlanStatus === "preparing" ? "Preparing Infrastructure Plan" : "Prepare Infrastructure Plan"}
                </button>
              </div>
            </section>

            <div className="workflow-step-body">
            <section className="guided-review" aria-label="Infrastructure plan review">
              <div className="section-heading">
                <h3>Deployment Scope</h3>
                <span aria-live="polite" role="status">{corePlanStatus === "loading" ? "loading saved plan" : corePlanStatus}</span>
              </div>
              <div className="detail-grid test-deploy-grid deployment-checkout-review">
                <div>
                  <span>Engagement</span>
                  <strong>{selectedEngagement?.name ?? guidedEngagementName ?? "not set"}</strong>
                </div>
                <div>
                  <span>Sketch state mode</span>
                  <strong>{engagementSketchStateSchema === "provider-keyed-v2" ? "Provider-keyed pilot" : "Standard"}</strong>
                  {corePlan ? <small>Saved plan: {planSketchStateSchema === "provider-keyed-v2" ? "Provider-keyed pilot" : "Standard"}</small> : null}
                </div>
                <div>
                  <span>Template</span>
                  <strong>{reviewedConfiguration?.templateName ?? selectedInfrastructureTemplate?.name ?? selectedInfrastructureTemplateId}</strong>
                </div>
                <div>
                  <span>Target and region</span>
                  <strong>{reviewedConfiguration ? `${reviewedConfiguration.target.name} · ${reviewedConfiguration.target.region}` : `${selectedDeploymentTarget?.name ?? "loading"} · ${selectedDeploymentTarget?.region ?? "loading"}`}</strong>
                </div>
                <div>
                  <span>Core nodes</span>
                  <strong>{reviewedConfiguration?.core.homebases ?? 1} homebase, {reviewedConfiguration?.core.proxies ?? activeInfrastructureProxyOptions.length} prox{(reviewedConfiguration?.core.proxies ?? activeInfrastructureProxyOptions.length) === 1 ? "y" : "ies"}</strong>
                </div>
                <div>
                  <span>ELK</span>
                  <strong>{(reviewedConfiguration?.core.elkEnabled ?? guidedDeploymentInput.elkEnabled) ? "1 node" : "Not included"}</strong>
                </div>
                <div>
                  <span>Trusted SSH CIDRs</span>
                  <strong>{reviewedConfiguration?.sshSourceCidrs.length ? reviewedConfiguration.sshSourceCidrs.join(", ") : sshSourceCidrs.length ? sshSourceCidrs.join(", ") : "Add at least one trusted CIDR in Step 1"}</strong>
                </div>
                <div>
                  <span>Execution order</span>
                  <strong>Core Terraform plan → core configuration and capabilities → validated sketch rollout</strong>
                </div>
              </div>
            </section>

              <section className="post-core-scope" aria-label="Validated post-core rollout">
                <h3>Validated Post-Core Rollout</h3>
                <p>This scope runs after the saved core plan and is not part of that Terraform artifact.</p>
                <ul>
                  {displayedPostCoreChains.map((chain) => {
                    const authorized = reviewedSketchAuthorization?.kind === "bounded-mixed-post-core-v1"
                      ? reviewedSketchAuthorization.providerScopes.find((scope) => scope.chain.id === chain.id)?.chain
                      : reviewedSketchAuthorization?.chains.find((item) => item.id === chain.id);
                    return (
                      <li key={chain.id}>
                        <strong>{chain.assignedProxy}</strong>
                        <span>→ {chain.middle.provider}/{chain.middle.region} middle{authorized ? ` (${authorized.middle.size})` : ""} → {chain.edges.map((edge, index) => `${edge.provider}/${edge.region} edge${authorized?.edges[index] ? ` (${authorized.edges[index].size})` : ""}`).join(", ")}</span>
                      </li>
                    );
                  })}
                </ul>
                {reviewedSketchAuthorization?.kind === "bounded-mixed-post-core-v1" ? (
                  <div aria-label="Reviewed Sketch authorization">
                    <p>{reviewedSketchAuthorization.providerScopes.map((scope) => `${scope.provider} image ${scope.image} · managed connection ${scope.providerConnectionId}`).join("; ")}</p>
                    <p>Each provider has its own reviewed Sketch state and firewall. Public TCP {reviewedSketchAuthorization.providerScopes[0]?.firewall.publicTcpPorts.join(", ")}; no public UDP or IPv6. Barragan checks both exact Sketch plans against the reviewed scope after core deployment.</p>
                  </div>
                ) : reviewedSketchAuthorization ? (
                  <div aria-label="Reviewed Sketch authorization">
                    <p>DigitalOcean image {reviewedSketchAuthorization.image} · managed connection {reviewedSketchAuthorization.providerConnectionId}</p>
                    <p>Public TCP {reviewedSketchAuthorization.firewall.publicTcpPorts.join(", ")}; no public UDP or IPv6. Management SSH is limited to the selected proxies’ public IPv4 /32 addresses assigned after core deployment. Barragan checks the exact Sketch plan against this scope before applying it.</p>
                    <p>Peer ingress from the created Sketch nodes permits TCP, UDP, and ICMP; outbound IPv4 is unrestricted. Barragan derives the peer addresses after creation and checks them against this reviewed rule.</p>
                  </div>
                ) : null}
              </section>

              {corePlanStatus === "failed" ? (
                <div className="plan-message blocked" role="alert">
                  <strong>Plan preparation failed.</strong>
                  <span>{corePlan?.error ?? "Check the plan inputs and try again."}</span>
                </div>
              ) : null}
              {corePlanStatus === "outdated" || corePlanStatus === "invalidated" ? (
                <div className="plan-message blocked" role="alert">
                  <strong>Plan is outdated.</strong>
                  <span>The configuration changed. Prepare a new plan before deployment.</span>
                </div>
              ) : null}
              {sketchStateSchemaMismatch ? (
                <div className="plan-message blocked" role="alert">
                  <strong>Plan state mode mismatch.</strong>
                  <span>The saved plan does not match this engagement's Sketch state mode. Prepare a new plan before deployment.</span>
                </div>
              ) : null}
              {corePlanIsOld ? (
                <div className="plan-message warning" role="status">
                  <strong>This plan is more than 60 minutes old.</strong>
                  <span>Review it carefully. Age alone does not expire the plan.</span>
                </div>
              ) : null}

              {corePlan ? (
                <section className="core-plan-result" aria-label="Saved core Terraform plan">
                  <div className="section-heading">
                    <div>
                      <h3>Core Terraform Changes</h3>
                      <p>Plan {corePlan.id}</p>
                    </div>
                    <span>{corePlan.stage}</span>
                  </div>
                  {reviewedComputeProfile ? <ComputeProfileReview profile={reviewedComputeProfile} /> : null}
                  <div className="plan-action-counts" aria-label="Terraform action counts">
                    {(["add", "update", "replace", "remove", "output"] as const).map((action) => (
                      <div key={action}>
                        <span>{action[0].toUpperCase() + action.slice(1)}</span>
                        <strong>{corePlan.counts[action] ?? 0}</strong>
                      </div>
                    ))}
                  </div>
                  {corePlanChangeTotal === 0 ? (
                    <div className="plan-message blocked" role="status"><strong>No core changes.</strong><span>This successful plan cannot be deployed.</span></div>
                  ) : null}
                  {corePlanHasDestructiveChanges ? (
                    <div className="plan-message blocked" role="alert"><strong>Deployment blocked.</strong><span>Replacement or removal is not allowed for new infrastructure.</span></div>
                  ) : null}
                  <div className="resource-change-groups">
                    {Object.entries(groupedCoreChanges).map(([group, changes]) => (
                      <section key={group} aria-label={`${group} resource changes`}>
                        <h4>{group}</h4>
                        <ul>
                          {changes.map((change) => (
                            <li key={`${change.action}-${change.address}`}>
                              <strong>{change.action[0].toUpperCase() + change.action.slice(1)}</strong>
                              <span>{change.displayName} · {change.type}{change.region ? ` · ${change.region}` : ""}</span>
                            </li>
                          ))}
                        </ul>
                      </section>
                    ))}
                  </div>
                  {corePlan.sanitizedText || corePlan.terraformFiles.length ? (
                    <details className="terraform-source-viewer">
                      <summary>Advanced Terraform evidence</summary>
                      <p>Sanitized plan output and allowlisted generated core source. State, credentials, keys, tfvars, and private paths are excluded.</p>
                      {corePlan.sanitizedText ? (
                        <pre aria-label={corePlan.sanitizedTextKind === "terraform_plan" ? "Sanitized Terraform plan" : "Sanitized plan summary"}><code>{corePlan.sanitizedText}</code></pre>
                      ) : null}
                      {corePlan.terraformFiles.length ? (
                        <>
                          <div className="terraform-source-tabs" role="tablist" aria-label="Generated Terraform files">
                            {corePlan.terraformFiles.map((file) => (
                              <button aria-selected={(selectedTerraformPath || corePlan.terraformFiles[0]?.path) === file.path} className="secondary-action compact" key={file.path} onClick={() => setSelectedTerraformPath(file.path)} role="tab" type="button">{file.path}</button>
                            ))}
                          </div>
                          {corePlan.terraformFiles.filter((file) => file.path === (selectedTerraformPath || corePlan.terraformFiles[0]?.path)).map((file) => (
                            <pre aria-label={`Terraform source ${file.path}`} key={file.path} role="tabpanel"><code>{file.content}</code></pre>
                          ))}
                        </>
                      ) : null}
                    </details>
                  ) : null}
                </section>
              ) : (
                <p className="guardrail-hint">Prepare the infrastructure plan to see exact core Terraform changes and the post-core rollout scope.</p>
              )}
            </div>
          </section>

          <section className="workflow-step-group test-deploy-view" aria-label="Infrastructure deployment">
            <section className="workflow-panel workflow-section-heading" aria-label="Step 3 Deploy and watch progress">
              <div>
                <h3 ref={deployStepHeadingRef} tabIndex={-1}>3. Deploy Infrastructure</h3>
                <p>Apply the exact saved core plan, then continue through the validated post-core rollout.</p>
              </div>
            </section>

            <div className="workflow-step-body">
              {!corePlanReady ? (
                <div className="gated-step" aria-disabled="true">
                  <strong>Deployment is locked.</strong>
                  <span>Prepare a current, successful infrastructure plan in Step 2.</span>
                </div>
              ) : null}

              {corePlanReady && testDeployReadiness ? (
                <>
                <section className="confirmation-panel" aria-label="Guided deployment confirmation">
                  <div className="section-heading">
                    <div>
                      <h3>{corePlan.target.name} · {corePlan.target.region}</h3>
                      <p>Apply {corePlan.counts.add} add, {corePlan.counts.update} update, and {corePlan.counts.output ?? 0} output action{corePlanChangeTotal === 1 ? "" : "s"} from plan {corePlan.id}; then continue with {reviewedPostCoreScope?.chainCount ?? 0} validated sketch chain{(reviewedPostCoreScope?.chainCount ?? 0) === 1 ? "" : "s"}.</p>
                    </div>
                    <span>{corePlanDeployable ? "ready" : "blocked"}</span>
                  </div>
                  <label>
                    <span>Confirmation token</span>
                    <input
                      aria-label="Confirmation token"
                      onChange={(event) => setTestDeployConfirmation(event.target.value)}
                      placeholder={testDeployReadiness.confirmationToken}
                      value={testDeployConfirmation}
                    />
                  </label>
                  <button className="primary-action" disabled={!guidedRunEnabled} onClick={() => onRunTestDeployment()} type="button">
                    {testDeployRunStatus === "running" && testDeployTeardownStatus !== "running" ? "Deploying" : "Deploy"}
                  </button>
                  <p className="guardrail-hint" aria-live="polite">{deployGuardrailMessage}</p>
                </section>

                {testDeployRunJob || testDeployRunStatus === "running" || testDeployRunStatus === "error" || showTeardownActivity ? (
                  <section className="confirmation-panel deployment-console-summary" aria-label="Infrastructure deployment console summary">
                    <div className="section-heading">
                      <div>
                        <h3>{showTeardownActivity ? "Teardown Console" : "Deployment Console"}</h3>
                        <p>{infrastructureConsoleSummary}</p>
                      </div>
                      <div className="section-actions">
                        <span>{activityStatus}</span>
                        {showTeardownActivity && finalCleanupStatus === "verified_clean" && !teardownInProgress ? (
                          <button
                            className="secondary-action compact"
                            onClick={onBeginTestDeploymentTeardown}
                            type="button"
                          >
                            Reconcile Cleanup
                          </button>
                        ) : null}
                        <button className="secondary-action compact" onClick={() => setInfrastructureConsoleOpen(true)} type="button">
                          <LaptopMinimalCheck aria-hidden="true" size={16} />
                          Open Console
                        </button>
                      </div>
                    </div>
                  </section>
                ) : null}

                {showTeardownActivity && testDeployTeardownStatus === "confirming" && testDeployRunJob ? (
                  <div className="teardown-confirmation" role="group" aria-label="Confirm cleanup reconciliation">
                    <div className="detail-grid test-deploy-grid deployment-checkout-review" aria-label="Engagement teardown scope">
                      {engagementTeardownPreviewStatus === "loading" ? (
                        <div><span>Cleanup scope</span><strong>Loading current Barragan-owned resources…</strong></div>
                      ) : engagementTeardownPreviewStatus === "error" ? (
                        <div><span>Cleanup scope</span><strong>Could not load the teardown scope. Cancel and try again.</strong></div>
                      ) : engagementTeardownPreview ? engagementTeardownPreview.orderedScope.map((scope, index) => (
                        <div key={scope.id}>
                          <span>{index + 1}. {scope.label}</span>
                          <strong>{engagementTeardownScopeSummary(scope)}</strong>
                        </div>
                      )) : null}
                    </div>
                    <label>
                      <span>Type {teardownPhrase} to confirm cleanup reconciliation</span>
                      <input
                        aria-label="Confirm tear down phrase"
                        onChange={(event) => setTestDeployTeardownConfirmation(event.target.value)}
                        placeholder={teardownPhrase}
                        value={testDeployTeardownConfirmation}
                      />
                    </label>
                    <button
                      className="secondary-action danger"
                      disabled={!teardownConfirmed}
                      onClick={onTeardownTestDeploymentRun}
                      type="button"
                    >
                      Confirm Tear Down
                    </button>
                    <button
                      className="secondary-action compact"
                      onClick={() => {
                        setTestDeployTeardownStatus("idle");
                        setTestDeployTeardownConfirmation("");
                      }}
                      type="button"
                    >
                      Cancel
                    </button>
                  </div>
                ) : null}

                {testDeployRunJob ? (
                  <section className="pilot-run-history" aria-label="Current deployment run">
                    <div className="section-heading">
                      <h3>Current core deployment</h3>
                      <div className="section-actions">
                        <span>{testDeployRunJob.status}</span>
                        <button className="secondary-action compact" onClick={onRefreshTestDeploymentRun} type="button">
                          Refresh
                        </button>
                      </div>
                    </div>
                    <div className="detail-grid test-deploy-grid">
                      <div>
                        <span>Job ID</span>
                        <strong>{testDeployRunJob.id}</strong>
                      </div>
                      <div>
                        <span>Workspace</span>
                        <strong>{pilotRunValue(testDeployRunJob, "workspace")}</strong>
                      </div>
                      <div>
                        <span>Infrastructure</span>
                        <strong>{pilotRunValue(testDeployRunJob, "mutationStatus")}</strong>
                      </div>
                      <div>
                        <span>Ansible</span>
                        <strong>{pilotRunValue(testDeployRunJob, "ansibleStatus")}</strong>
                      </div>
                      <div>
                        <span>Tear down</span>
                        <strong>{pilotRunValue(testDeployRunJob, "finalCleanupStatus")}</strong>
                      </div>
                    </div>
                    {connectionDetailsFromJob(testDeployRunJob).length > 0 ? (
                      <div className="table-panel embedded" aria-label="Connection details">
                        <TableHeader columns={["Host", "Public SSH", "Private IP", "Services"]} />
                        {connectionDetailsFromJob(testDeployRunJob).map((host) => (
                          <div className="table-row" key={`connection-${host.displayName}`}>
                            <span>{host.displayName}</span>
                            <code>{host.sshCommand}</code>
                            <span>{host.privateIp}</span>
                            <span>{host.services.join(", ")}</span>
                          </div>
                        ))}
                      </div>
                    ) : null}
                  </section>
                ) : null}

                </>
              ) : null}
            </div>
          </section>
          </>
          )}
        </div>
        ) : null}

        {activeEngagementTab === "channels" ? (
          <section className="workflow-stack channels-workspace" aria-label="Channels">
            <div className="filter-tabs channel-tabs" aria-label="Channel type">
              <button className={activeChannelTab === "outbound" ? "filter-tab active" : "filter-tab"} onClick={() => setActiveChannelTab("outbound")} type="button">
                Outbound
              </button>
              <button className={activeChannelTab === "inbound" ? "filter-tab active" : "filter-tab"} onClick={() => setActiveChannelTab("inbound")} type="button">
                Inbound
              </button>
            </div>

            {activeChannelTab === "outbound" ? (
              <section className="table-panel embedded operations-table channel-summary responsive-channel-table" aria-label="Outbound channel status summary">
                <div className="table-header channel-summary-heading">
                  <h3>Outbound channels</h3>
                  <span>{engagementOperations?.outboundChannels.length ?? 0} channels</span>
                </div>
                <p className="guardrail-hint">Barragan automatically configures and validates each standard route when its sketch chain is ready. Use Re-check only to diagnose a route after deployment; it does not change proxy configuration.</p>
                <TableHeader columns={["Profile", "Proxy", "Edge", "SOCKS Port", "Expected Egress IP", "Status", "Last Checked", "Actions"]} />
                {engagementOperations?.outboundChannels.length ? (
                  engagementOperations.outboundChannels.map((channel) => {
                    const chainId = outboundChannelActionId(channel);
                    const previewReady = outboundChannelAction.activeChainId === chainId && Boolean(outboundChannelAction.preview);
                    const applying = outboundChannelAction.activeChainId === chainId && outboundChannelAction.status === "running";
                    const status = operationValue(channel.validation?.status ?? channel.status, "").toLowerCase();
                    const canValidate = status.includes("pending validation") || status.includes("validated");
                    const applyConfirmation = outboundChannelAction.applyConfirmations[chainId] ?? "";
                    return (
                      <div className="table-row channel-management-row" key={`outbound-summary-${chainId}`}>
                        <span data-label="Profile">{outboundProfileLabel(channel.profileName, chainId)}</span>
                        <span data-label="Proxy">{operationValue(channel.proxy, "N/A")}</span>
                        <span data-label="Edge">{operationValue(channel.edge, "Not Deployed")}</span>
                        <span data-label="SOCKS port">{operationValue(channel.port, "N/A")}</span>
                        <span data-label="Expected egress IP">{operationValue(channel.validation?.expectedPublicIp, "Not Recorded")}</span>
                        <div data-label="Status"><StatusPill value={operatorChannelStatus(channel.validation?.status ?? channel.status)} /></div>
                        <span data-label="Last checked">{formatOperationsTimestamp(channel.validation?.checkedAt ?? channel.validation?.lastCheckedAt)}</span>
                        <span className="row-actions outbound-channel-actions" data-label="Actions">
                          <button
                            className="secondary-action compact"
                            disabled={applying}
                            onClick={() => onPreviewOutboundChannelApply(chainId)}
                            type="button"
                          >
                            {applying ? "Working…" : "Preview Apply"}
                          </button>
                          {previewReady ? (
                            <label>
                              <span>Type {applyOutboundConfirmationToken(chainId)}</span>
                              <input
                                aria-label={`Apply outbound confirmation for ${chainId}`}
                                onChange={(event) => onUpdateOutboundChannelConfirmation(chainId, event.target.value)}
                                type="text"
                                value={applyConfirmation}
                              />
                              <button
                                className="primary-action compact"
                                disabled={applying || applyConfirmation !== applyOutboundConfirmationToken(chainId)}
                                onClick={() => onApplyOutboundChannel(chainId)}
                                type="button"
                              >
                                Apply
                              </button>
                            </label>
                          ) : null}
                          {canValidate ? (
                            <button
                              className="secondary-action compact"
                              disabled={applying}
                              onClick={() => onValidateOutboundChannel(chainId)}
                              type="button"
                            >
                              Re-check
                            </button>
                          ) : null}
                          {outboundChannelAction.activeChainId === chainId && outboundChannelAction.message ? (
                            <small role="status">{outboundChannelAction.message}</small>
                          ) : null}
                        </span>
                      </div>
                    );
                  })
                ) : (
                  <OperationsEmptyState message="No outbound channels are recorded yet. Deploy sketch chains from Infrastructure to create the standard egress routes." />
                )}
              </section>
            ) : null}

            {activeChannelTab === "inbound" ? (
              <section className="table-panel embedded operations-table channel-summary responsive-channel-table" aria-label="Inbound channel status summary">
                <div className="table-header channel-summary-heading">
                  <h3>Inbound channels</h3>
                  <div className="section-actions">
                    {inboundBatchJob ? <button className="secondary-action compact" onClick={() => setInboundBatchConsoleOpen(true)} type="button">Latest batch</button> : null}
                    <button
                      className="primary-action compact"
                      onClick={() => {
                        setInboundComposerOpen(true);
                        setInboundRemoveTarget(null);
                      }}
                      type="button"
                    >
                      Add Inbound Channel
                    </button>
                  </div>
                </div>
                <TableHeader columns={["Channel", "Edge Port", "Route", "Purpose", "Status", "Last Checked", "Actions"]} />
                {engagementOperations?.inboundChannels.length ? (
                  engagementOperations.inboundChannels.map((channel) => {
                    const removed = operationValue(channel.status, "").toLowerCase() === "removed";
                    const pendingApply = operationValue(channel.status, "").toLowerCase() === "pending apply";
                    const validationStatus = operationValue(channel.validation?.status ?? channel.status, "").toLowerCase();
                    const canRecheck = channel.validationProfile?.type !== "manual"
                      && ["pending validation", "validation failed", "validated"].includes(validationStatus);
                    const previewReady = inboundChannelAction.activeChannelId === channel.channelId && Boolean(inboundChannelAction.preview);
                    const applying = inboundChannelAction.activeChannelId === channel.channelId && inboundChannelAction.status === "running";
                    const applyConfirmation = inboundChannelAction.applyConfirmations[channel.channelId] ?? "";
                    return (
                      <div className="table-row channel-management-row" key={`inbound-summary-${channel.channelId}`}>
                        <span data-label="Channel">{operationValue(channel.channelId, "N/A")}</span>
                        <span data-label="Edge port">{operationValue(channel.edge, "Not Deployed")}:{operationValue(channel.externalPort, "N/A")}</span>
                        <span data-label="Route">{operationValue(channel.terminatesOn, "Not Ready")}:{operationValue(channel.internalPort, "N/A")}</span>
                        <span data-label="Purpose">{operationValue(channel.purpose, "Inbound route")}</span>
                        <div data-label="Status"><InboundValidationStatus channel={channel} /></div>
                        <span data-label="Last checked">{formatOperationsTimestamp(channel.validation?.checkedAt ?? channel.validation?.lastCheckedAt)}</span>
                        <span className="row-actions" data-label="Actions">
                          {removed ? (
                            <button
                              className="secondary-action compact"
                              onClick={() => {
                                setChannelConsoleOpen(true);
                                onRecoverInboundChannel(channel);
                              }}
                              type="button"
                            >
                              Restore
                            </button>
                          ) : (
                            <>
                              <button
                                className="secondary-action compact"
                                disabled={applying}
                                onClick={() => onPreviewInboundChannelApply(channel.channelId)}
                                type="button"
                              >
                                {applying ? "Working…" : pendingApply ? "Preview Apply" : "Preview Reapply"}
                              </button>
                              {previewReady ? (
                                <label>
                                  <span>Type {applyInboundConfirmationToken(channel.channelId)}</span>
                                  <input
                                    aria-label={`${pendingApply ? "Apply" : "Reapply"} inbound confirmation for ${channel.channelId}`}
                                    onChange={(event) => onUpdateInboundChannelConfirmation(channel.channelId, "apply", event.target.value)}
                                    type="text"
                                    value={applyConfirmation}
                                  />
                                  <button
                                    className="primary-action compact"
                                    disabled={applying || applyConfirmation !== applyInboundConfirmationToken(channel.channelId)}
                                    onClick={() => {
                                      setChannelConsoleOpen(true);
                                      onApplyInboundChannel(channel.channelId);
                                    }}
                                    type="button"
                                  >
                                    {pendingApply ? "Apply" : "Reapply"}
                                  </button>
                                </label>
                              ) : null}
                              {inboundChannelSupportsRequestHeaderGate(channel) ? (
                                <button className="secondary-action compact" onClick={() => openRequestHeaderGateManager(channel)} type="button">
                                  Configure
                                </button>
                              ) : null}
                              {inboundChannelSupportsCertificate(channel) ? (
                                <button className="secondary-action compact" onClick={() => openCertificateManager(channel)} type="button">
                                  Manage Cert
                                </button>
                              ) : null}
                              {canRecheck ? (
                                <button
                                  className="secondary-action compact"
                                  disabled={applying}
                                  onClick={() => {
                                    setChannelConsoleOpen(true);
                                    onValidateInboundChannel(channel.channelId);
                                  }}
                                  type="button"
                                >
                                  Re-check
                                </button>
                              ) : null}
                              <button className="danger-action compact" onClick={() => setInboundRemoveTarget(channel)} type="button">
                                Remove
                              </button>
                              {inboundChannelAction.activeChannelId === channel.channelId && inboundChannelAction.message ? (
                                <small role="status">{inboundChannelAction.message}</small>
                              ) : null}
                            </>
                          )}
                        </span>
                        <ManagedRouteDetails engagementId={selectedEngagementId} channelId={channel.channelId} />
                      </div>
                    );
                  })
                ) : (
                  <OperationsEmptyState message="No inbound channels have been added yet." />
                )}
              </section>
            ) : null}

            {inboundComposerOpen ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-floating-panel" aria-label="Add inbound channel">
                  <div className="section-heading">
                    <div>
                      <h3>Add inbound channel</h3>
                      <p>Select an edge and Barragan will lock the middle/proxy path.</p>
                    </div>
                    <button className="secondary-action compact" onClick={closeInboundBatchComposer} type="button">
                      Cancel
                    </button>
                  </div>
                  {inboundBatchRows.length ? (
                    <div className="batch-channel-list" aria-label="Inbound batch rows">
                      <div className="section-heading">
                        <div>
                          <h4>Channels in this batch</h4>
                          <p>{inboundBatchRows.length} saved of 20 maximum. They will apply in this order.</p>
                        </div>
                      </div>
                      {inboundBatchRows.map((row, index) => (
                        <div className="table-row channel-management-row" key={row.localId}>
                          <span>{index + 1}. {row.body.protocol} {row.body.edge}:{row.body.externalPort}</span>
                          <span>{row.body.domain || `${row.body.terminatesOn}:${row.body.internalPort}`}</span>
                          <span className="row-actions">
                            <button className="secondary-action compact" onClick={() => {
                              setInboundBatchEditingId(row.localId);
                              setInboundChannelDraft({ ...emptyInboundChannelForm, ...row.body, validationProfile: row.body.validationProfile ?? { ...defaultInboundValidationProfile } });
                              invalidateInboundBatchPreview();
                            }} type="button">Edit</button>
                            <button className="secondary-action compact" disabled={inboundBatchRows.length >= 20} onClick={() => {
                              setInboundBatchRows((current) => [...current, { localId: crypto.randomUUID(), body: { ...row.body } }]);
                              invalidateInboundBatchPreview();
                            }} type="button">Duplicate</button>
                            <button className="danger-action compact" onClick={() => {
                              setInboundBatchRows((current) => current.filter((candidate) => candidate.localId !== row.localId));
                              if (inboundBatchEditingId === row.localId) {
                                setInboundBatchEditingId(null);
                                setInboundChannelDraft({ ...emptyInboundChannelForm });
                              }
                              invalidateInboundBatchPreview();
                            }} type="button">Remove</button>
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <div className="form-grid channel-modal-grid">
                    <label>
                      <span>Edge</span>
                      <select
                        aria-label="Inbound edge"
                        onChange={(event) => {
                          const option = inboundHostOptions.edges.find((candidate) => candidate.value === event.target.value);
                          const attachment = option
                            ? inboundEdgeAttachment(engagementOperations, option.chainId, option.componentId, option.hostname, inboundEngagementName)
                            : null;
                          updateInboundChannel({
                            chainId: option?.chainId ?? "",
                            edgeComponentId: option?.componentId ?? "",
                            edge: option?.hostname ?? "",
                            middle: attachment?.middleHostname ?? "",
                            middleComponentId: attachment?.middleComponentId ?? "",
                            proxy: attachment?.proxyHostname ?? "",
                            terminatesOn: attachment?.proxyHostname ?? ""
                          });
                        }}
                        value={inboundEdgeOptionValue(inboundChannelDraft.chainId, inboundChannelDraft.edgeComponentId)}
                      >
                        <option value="">Select edge</option>
                        {inboundHostOptions.edges.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </label>
                    <label>
                      <span>Mode</span>
                      <select
                        aria-label="Inbound mode"
                        onChange={(event) => {
                          const mode = event.target.value;
                          updateInboundChannel({
                            mode,
                            protocol: mode === "udp-forward" ? "UDP" : mode === "https-openresty" ? "HTTPS" : mode === "http-openresty" ? "HTTP" : "TCP"
                          });
                        }}
                        value={inboundChannelDraft.mode}
                      >
                        <option value="tcp-forward">TCP forward</option>
                        <option value="http-openresty">HTTP/OpenResty</option>
                        <option value="https-openresty">HTTPS/OpenResty</option>
                        <option value="udp-forward">UDP forward</option>
                      </select>
                    </label>
                    <label>
                      <span>External edge port</span>
                      <input aria-label="Inbound external port" onChange={(event) => updateInboundChannel({ externalPort: event.target.value })} placeholder="443" value={inboundChannelDraft.externalPort} />
                    </label>
                    <label>
                      <span>Terminates on</span>
                      <select
                        aria-label="Inbound termination"
                        disabled={!inboundTerminationOptions.length}
                        onChange={(event) => updateInboundChannel({ terminatesOn: event.target.value })}
                        value={inboundChannelDraft.terminatesOn}
                      >
                        <option value="">Select termination</option>
                        {inboundTerminationOptions.map((option) => (
                          <option key={option.value} value={option.value}>{option.label}</option>
                        ))}
                      </select>
                    </label>
                    {bindableServiceOptions.length ? (
                      <label>
                        <span>Service</span>
                        <select
                          aria-label="Inbound service"
                          onChange={(event) => {
                            const service = bindableServiceOptions.find((placement) => placement.serviceId === event.target.value);
                            if (!service) {
                              updateInboundChannel({ service: "", serviceId: "", serviceType: "" });
                              return;
                            }
                            const domain = service.domain || inboundChannelDraft.domain;
                            const isStaticWebService = service.serviceType === "web-static";
                            const isManagedGoSUS = service.serviceType === "capability-http-backend" && service.service === "Go Simple Upload Server";
                            const serviceTermination = isManagedGoSUS
                              ? inboundAttachment?.proxyHostname ?? ""
                              : service.hostId === "homebase"
                              ? inboundAttachment?.homebaseHostname ?? "homebase"
                              : webStaticTerminationHost(engagementOperations, service.hostId || "");
                            const serviceProtocol = String(service.protocol || "tcp").toLowerCase();
                            const isUdpService = serviceProtocol === "udp";
                            updateInboundChannel({
                              protocol: isUdpService ? "UDP" : isStaticWebService ? "HTTP" : isManagedGoSUS ? "HTTPS" : "TCP",
                              mode: isUdpService ? "udp-forward" : isStaticWebService ? "http-openresty" : isManagedGoSUS ? "https-openresty" : "tcp-forward",
                              externalPort: isStaticWebService ? "80" : isManagedGoSUS ? "443" : inboundChannelDraft.externalPort,
                              service: service.service,
                              serviceId: service.serviceId ?? "",
                              serviceType: service.serviceType ?? "",
                              terminatesOn: serviceTermination,
                              internalPort: isStaticWebService ? "80" : service.port,
                              domain,
                              purpose: isStaticWebService
                                ? `${service.siteName || service.domain || "Static Web"} web traffic`
                                : service.purpose || `${service.siteName || service.domain || service.service || "Service"} ingress`,
                              validationProfile: isStaticWebService
                                ? {
                                    type: "http",
                                    label: "HTTP response"
                                  }
                                : isManagedGoSUS
                                  ? {
                                      type: "manual",
                                      label: "Bind TLS certificate, then validate HTTPS upload from Inspector"
                                    }
                                : service.validationProfile ?? defaultValidationProfileForGenericProtocol(serviceProtocol)
                            });
                          }}
                          value={inboundChannelDraft.serviceId || ""}
                        >
                          <option value="">Manual target</option>
                          {bindableServiceOptions.map((placement) => (
                            <option key={`inbound-service-${placement.serviceId}`} value={placement.serviceId}>
                              {placement.siteName || placement.service || placement.domain || placement.serviceId} {placement.serviceType === "web-static" ? `on ${placement.hostId} shared web front` : `on ${placement.hostId}:${placement.port}${placement.serviceType === "capability-http-backend" ? " (managed HTTPS)" : ""}`}
                            </option>
                          ))}
                        </select>
                      </label>
                    ) : null}
                    {!inboundChannelDraft.serviceId ? (
                      <label>
                        <span>Backend service</span>
                        <input aria-label="Inbound backend service" onChange={(event) => updateInboundChannel({ service: event.target.value })} placeholder="File service" value={inboundChannelDraft.service} />
                      </label>
                    ) : null}
                    <label>
                      <span>Internal port</span>
                      <input aria-label="Inbound internal port" disabled={inboundChannelDraft.serviceType === "web-static"} onChange={(event) => updateInboundChannel({ internalPort: event.target.value })} placeholder="18080" value={inboundChannelDraft.internalPort} />
                    </label>
                    <label>
                      <span>Domain</span>
                      <input aria-label="Inbound domain" onChange={(event) => updateInboundChannel({ domain: event.target.value })} placeholder="www.example.com" value={inboundChannelDraft.domain} />
                    </label>
                    <label className="wide-field">
                      <span>Purpose</span>
                      <input aria-label="Inbound purpose" onChange={(event) => updateInboundChannel({ purpose: event.target.value })} placeholder="Campaign web traffic" value={inboundChannelDraft.purpose} />
                    </label>
                  </div>
                  <div className="inline-info">
                    <strong>{inboundAttachment ? `Path: ${inboundAttachment.edgeHostname} -> ${inboundAttachment.middleHostname} -> ${inboundAttachment.proxyHostname}` : "Select an edge to see its locked path."}</strong>
                  </div>
                  {inboundBackflipsWarning ? (
                    <div className="inline-warning channel-modal-warning" role="alert">
                      {inboundBackflipsWarning}
                    </div>
                  ) : null}
                  <InboundPublicIngressPolicyHint channel={inboundChannelDraft} operations={engagementOperations} />
                  {inboundBatchPreview ? (
                    <div className="inline-info batch-review" role="status" aria-label="Reviewed inbound batch">
                      <strong>{inboundBatchPreview.summary}</strong>
                      {inboundBatchPreview.channels.map((channel, index) => (
                        <div key={channel.channelId ?? index}>
                          <span>
                            {index + 1}. {channel.protocol} {channel.edge}:{channel.externalPort}
                            {channel.middle ? ` → ${channel.middle}:${channel.middleRelayPort || channel.externalPort}` : ""}
                            {channel.proxy ? ` → ${channel.proxy}:${channel.proxyRelayPort || channel.externalPort}` : ""}
                            {` → ${channel.terminatesOn}:${channel.internalPort}`}
                            {channel.domain ? ` · ${channel.domain}` : ""}
                            {channel.service ? ` · ${channel.service}` : ""}
                          </span>
                          {channel.ingressAssessment?.checks?.length ? (
                            <details>
                              <summary>Managed provider and host firewall scope</summary>
                              {channel.ingressAssessment.checks.map((check) => (
                                <span key={`${channel.channelId}-${check.id}`}>{check.label}: {check.host}:{check.port}/{check.protocol}{check.source ? ` from ${check.source}` : ""}</span>
                              ))}
                            </details>
                          ) : <span>Managed provider and host firewall scope</span>}
                        </div>
                      ))}
                      {inboundBatchPreview.warnings.map((warning) => <span className="inline-warning" key={warning}>{warning}</span>)}
                    </div>
                  ) : null}
                  {inboundBatchMessage ? <p className={inboundBatchStatus === "error" ? "inline-warning" : "guardrail-hint"} role="status">{inboundBatchMessage}</p> : null}
                  <div className="form-actions">
                    {inboundBatchRows.length === 0 && !inboundBatchPreview ? (
                      <button className="primary-action" disabled={!inboundCreateReady} onClick={() => {
                        onCreateInboundChannel(inboundRequestFromDraft());
                        setInboundComposerOpen(false);
                        setChannelConsoleOpen(true);
                      }} type="button">Apply</button>
                    ) : null}
                    {!inboundBatchPreview ? (
                      <button className="secondary-action" disabled={!inboundCreateReady || inboundBatchRows.length >= 20} onClick={addCurrentInboundBatchRow} type="button">
                        {inboundBatchEditingId ? "Save row" : "Add another"}
                      </button>
                    ) : null}
                    {inboundBatchPreview && inboundBatchRows.length === 1 ? (
                      <button className="secondary-action" disabled={inboundBatchStatus === "saving" || inboundBatchStatus === "applying"} onClick={saveCurrentInboundPending} type="button">
                        {inboundBatchStatus === "saving" ? "Saving…" : "Save Pending"}
                      </button>
                    ) : null}
                    {inboundBatchRows.length ? (
                      <button className={inboundBatchPreview ? "primary-action" : "secondary-action"} disabled={inboundBatchStatus === "previewing" || inboundBatchStatus === "saving" || inboundBatchStatus === "applying"} onClick={inboundBatchPreview ? applyCurrentInboundBatch : previewCurrentInboundBatch} type="button">
                        {inboundBatchStatus === "previewing" ? "Reviewing…" : inboundBatchStatus === "applying" ? "Applying…" : inboundBatchPreview ? `Apply ${inboundBatchRows.length} ${inboundBatchRows.length === 1 ? "channel" : "channels"}` : `Review ${inboundBatchRows.length + (inboundCreateReady ? 1 : 0)} channels`}
                      </button>
                    ) : null}
                    <button className="secondary-action" onClick={closeInboundBatchComposer} type="button">
                      Close
                    </button>
                  </div>
                </section>
              </div>
            ) : null}

            {inboundRemoveTarget ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-floating-panel" aria-label="Remove inbound channel">
                  <div className="section-heading">
                    <div>
                      <h3>Remove inbound channel</h3>
                      <p>{inboundRemoveTarget.channelId}</p>
                    </div>
                  </div>
                  <p>Remove this inbound channel configuration? The record will remain available for restore.</p>
                  <div className="form-actions">
                    <button
                      className="danger-action"
                      onClick={() => {
                        onRemoveInboundChannel(inboundRemoveTarget);
                        setInboundRemoveTarget(null);
                        setChannelConsoleOpen(true);
                      }}
                      type="button"
                    >
                      Confirm
                    </button>
                    <button className="secondary-action" onClick={() => setInboundRemoveTarget(null)} type="button">
                      Cancel
                    </button>
                  </div>
                </section>
              </div>
            ) : null}

            {requestHeaderGateManagerOpen ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-floating-panel request-header-gate-panel" aria-label="Request header access gate">
                  <div className="section-heading">
                    <div>
                      <h3>Configure inbound channel</h3>
                      <p>Control who can send requests through this route.</p>
                    </div>
                    <button className="secondary-action compact" onClick={closeRequestHeaderGateManager} type="button">Close</button>
                  </div>
                  <div className="request-header-gate-scroll-body">
                    {requestHeaderGateAction.channel ? (
                      <dl className="compact-summary request-header-gate-summary">
                        <div><dt>Host</dt><dd>{operationValue(requestHeaderGateAction.channel.domain, "N/A")}</dd></div>
                        <div><dt>Public listener</dt><dd>{operationValue(requestHeaderGateAction.channel.edge, "edge")}:{operationValue(requestHeaderGateAction.channel.externalPort, "N/A")}</dd></div>
                        <div><dt>Path</dt><dd>{operationValue(requestHeaderGateAction.channel.edge, "edge")} → {operationValue(requestHeaderGateAction.channel.middle, "middle")} → {operationValue(requestHeaderGateAction.channel.proxy, "proxy")}</dd></div>
                        <div><dt>Backend</dt><dd>{operationValue(requestHeaderGateAction.channel.terminatesOn, "target")}:{operationValue(requestHeaderGateAction.channel.internalPort, "N/A")} · {operationValue(requestHeaderGateAction.channel.service, "service")}</dd></div>
                      </dl>
                    ) : null}
                    {requestHeaderGateAction.workspace ? (
                      <section className="request-header-gate-policy inbound-request-size-policy" aria-label="Request size policy">
                        <div className="form-grid request-header-gate-form">
                          <label className="wide-field">
                            <span>Maximum request body (MB)</span>
                            <input
                              aria-label="Maximum request body MB"
                              disabled={requestHeaderGateAction.status === "running" || requestGateIsManagedGoSUS}
                              inputMode="numeric"
                              max={requestHeaderGateAction.workspace.backendPolicy?.maxRequestBodyMb ?? 10240}
                              min={1}
                              onChange={(event) => setRequestHeaderGateAction((current) => ({
                                ...current,
                                maxRequestBodyMb: event.target.value
                              }))}
                              step={1}
                              type="number"
                              value={requestHeaderGateAction.maxRequestBodyMb}
                            />
                            <small>
                              Barragan uses decimal megabytes (1 MB = 1,000,000 bytes) and renders the exact byte limit in OpenResty. Default: 500 MB. Larger uploads require enough proxy capacity and may take longer to relay.
                            </small>
                            {requestHeaderGateAction.workspace.backendPolicy ? (
                              <small>
                                {requestGateIsManagedGoSUS
                                  ? `GoSUS accepts uploads up to ${requestHeaderGateAction.workspace.backendPolicy.maxRequestBodyMb} MB. Its established client value is also this route's mandatory request gate.`
                                  : `Selected backend capability accepts requests up to ${requestHeaderGateAction.workspace.backendPolicy.maxRequestBodyMb} MB.`}
                              </small>
                            ) : null}
                            {!requestHeaderGateMaxBodyIsValid(requestHeaderGateAction.maxRequestBodyMb, requestHeaderGateAction.workspace.backendPolicy?.maxRequestBodyMb) ? (
                              <small className="error-text" role="alert">Enter a whole number from 1 through {requestHeaderGateAction.workspace.backendPolicy?.maxRequestBodyMb ?? 10240} MB.</small>
                            ) : null}
                          </label>
                        </div>
                      </section>
                    ) : null}
                    <label className="toggle-field request-header-gate-toggle">
                      <input
                        aria-label="Enable bearer request gate"
                        checked={requestHeaderGateAction.enabled}
                        disabled={!requestHeaderGateAction.workspace || requestHeaderGateAction.status === "loading" || requestHeaderGateAction.status === "running" || requestGateIsManagedGoSUS}
                        onChange={(event) => setRequestHeaderGateAction((current) => ({ ...current, enabled: event.target.checked, copyStatus: "idle" }))}
                        type="checkbox"
                      />
                      <span>
                        <strong>Bearer request gate</strong>
                        <small>{requestGateIsManagedGoSUS ? "GoSUS requires this established value before the route proxies any request." : "Require one HTTP header and bearer token for every request on this Host route."}</small>
                      </span>
                    </label>
                    {requestHeaderGateAction.workspace ? (
                      <>
                      {requestHeaderGateAction.enabled ? (
                        <section className="request-header-gate-policy" aria-label="Request access policy">
                          <div className="section-heading compact-heading">
                            <div>
                              <h4>Request access policy</h4>
                              <p>These exact plaintext values will be retained with the engagement infrastructure.</p>
                            </div>
                          </div>
                          <div className="form-grid request-header-gate-form">
                            <label>
                              <span>HTTP header name</span>
                              <input
                                aria-label="Request gate header name"
                                disabled={requestHeaderGateAction.status === "running" || requestGateIsManagedGoSUS}
                                onChange={(event) => setRequestHeaderGateAction((current) => ({ ...current, headerName: event.target.value, copyStatus: "idle" }))}
                                value={requestHeaderGateAction.headerName}
                              />
                              <small>The request value is <code>Bearer &lt;token&gt;</code>.</small>
                              {!requestHeaderGateHeaderIsValid(requestHeaderGateAction.headerName) ? (
                                <small className="error-text" role="alert">Use a 1–64 character HTTP header name beginning with a letter. Hop-by-hop and routing headers are not allowed.</small>
                              ) : null}
                            </label>
                            <label className="wide-field">
                              <span>Bearer token</span>
                              <div className="request-header-gate-token-row">
                                <input
                                  aria-label="Request gate bearer token"
                                  autoComplete="off"
                                  disabled={requestHeaderGateAction.status === "running" || requestGateIsManagedGoSUS}
                                  maxLength={20}
                                  onChange={(event) => setRequestHeaderGateAction((current) => ({ ...current, token: event.target.value, copyStatus: "idle" }))}
                                  type="text"
                                  value={requestHeaderGateAction.token}
                                />
                                <button
                                  className="secondary-action compact"
                                  disabled={!requestHeaderGateAction.token || requestHeaderGateAction.status === "running"}
                                  onClick={() => copyRequestHeaderGateValue(requestHeaderGateAction.token, "token")}
                                  type="button"
                                >
                                  <Copy size={14} /> {requestHeaderGateAction.copyStatus === "token" ? "Copied" : "Copy"}
                                </button>
                                <button className="secondary-action compact" disabled={requestHeaderGateAction.status === "running" || requestGateIsManagedGoSUS} onClick={generateRequestHeaderGateToken} type="button">
                                  Generate
                                </button>
                              </div>
                              <small>{requestGateIsManagedGoSUS ? "This is GoSUS operator client configuration. It is retained and cannot be changed or disabled from this route." : "8–20 URL-safe characters. Generate replaces this field locally; it does not apply until you save."}</small>
                              {!requestHeaderGateProvidedTokenIsValid(requestHeaderGateAction.token) ? (
                                <small className="error-text" role="alert">Use 8–20 URL-safe token characters.</small>
                              ) : null}
                            </label>
                          </div>
                          {requestHeaderGateDraftCurl(requestHeaderGateAction.workspace, requestHeaderGateAction.headerName, requestHeaderGateAction.token) ? (
                            <section className="request-header-gate-example" aria-label="Authorized GET example">
                              <div className="section-heading compact-heading">
                                <div><h4>Authorized GET example</h4><p>This preview uses the values shown above. Save changes before running it.</p></div>
                                <button
                                  className="secondary-action compact"
                                  onClick={() => copyRequestHeaderGateValue(requestHeaderGateDraftCurl(requestHeaderGateAction.workspace!, requestHeaderGateAction.headerName, requestHeaderGateAction.token), "curl")}
                                  type="button"
                                >
                                  <Copy size={14} /> {requestHeaderGateAction.copyStatus === "curl" ? "Copied" : "Copy curl"}
                                </button>
                              </div>
                              <pre>{requestHeaderGateDraftCurl(requestHeaderGateAction.workspace, requestHeaderGateAction.headerName, requestHeaderGateAction.token)}</pre>
                            </section>
                          ) : null}
                        </section>
                      ) : null}
                        {requestHeaderGateAction.copyStatus === "error" ? <p className="inline-warning" role="alert">Clipboard access failed. Select and copy the value directly.</p> : null}
                        <p className={`guardrail-hint ${requestHeaderGateAction.status === "error" ? "error-text" : ""}`} role="status">{requestHeaderGateAction.message}</p>
                      </>
                    ) : (
                      <p className={`guardrail-hint ${requestHeaderGateAction.status === "error" ? "error-text" : ""}`} role="status">{requestHeaderGateAction.message}</p>
                    )}
                  </div>
                  {requestHeaderGateAction.workspace ? (
                    <div className="form-actions">
                      <button
                        className="primary-action"
                        disabled={!requestHeaderGateFormReady(requestHeaderGateAction)}
                        onClick={applyRequestHeaderGate}
                        type="button"
                      >
                        {requestHeaderGateAction.status === "running" ? "Saving channel policy…" : requestHeaderGateAction.status === "error" ? "Retry channel policy" : "Save channel policy"}
                      </button>
                      <button className="secondary-action" onClick={closeRequestHeaderGateManager} type="button">Cancel</button>
                    </div>
                  ) : null}
                </section>
              </div>
            ) : null}

            {certificateManagerOpen ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel certificate-floating-panel" aria-label="SSL/TLS Cert Manager">
                  <div className="section-heading">
                    <div>
                      <h3>Certificate binding</h3>
                      <p>{certificateAction.bindingWorkspace?.channel?.channelId ?? certificateAction.activeChannelId ?? "HTTPS inbound channel"}</p>
                    </div>
                    <div className="section-actions">
                      {certificateAction.job ? <button className="secondary-action compact" onClick={() => setCertificateConsoleOpen(true)} type="button">Log</button> : null}
                      <button className="secondary-action compact" onClick={() => setCertificateManagerOpen(false)} type="button">Close</button>
                    </div>
                  </div>
                  <dl className="compact-summary"><div><dt>Route</dt><dd>{certificateAction.bindingWorkspace?.routeStatus || "unknown"}</dd></div><div><dt>TLS</dt><dd>{certificateAction.bindingWorkspace?.tlsStatus || "unbound"}</dd></div><div><dt>Hostname</dt><dd>{certificateAction.bindingWorkspace?.channel?.domain || "N/A"}</dd></div></dl>
                  <p className="guardrail-hint">Certificate authoring and lifecycle actions live in the engagement Certificates workspace. This channel only selects an active, covering certificate on the same proxy.</p>
                  <label><span>Covering certificate</span><select aria-label="Covering certificate" onChange={(event) => setBindingCertificateId(event.target.value)} value={bindingCertificateId}><option value="">TLS Unbound</option>{certificateAction.bindingWorkspace?.candidates.map((certificate) => <option key={certificate.id} value={certificate.id}>{certificate.name} · {certificate.source} · {certificate.identifiers.join(", ")}</option>)}</select></label>
                  {certificateAction.bindingWorkspace?.certificate ? <p>Currently selected: <strong>{certificateAction.bindingWorkspace.certificate.name}</strong> ({certificateAction.bindingWorkspace.binding?.status}).</p> : null}
                  <p className="guardrail-hint">{certificateAction.message}</p>
                  <div className="form-actions">
                    <button className="primary-action" disabled={!bindingCertificateId || certificateAction.status === "running"} onClick={saveCertificateBinding} type="button">Bind certificate</button>
                    <button className="secondary-action" disabled={!certificateAction.bindingWorkspace?.binding} onClick={removeCertificateBinding} type="button">Unbind</button>
                    <button className="secondary-action" onClick={() => { setCertificateManagerOpen(false); setActiveEngagementTab("certificates"); }} type="button">Open Certificates</button>
                  </div>
                </section>
              </div>
            ) : null}

            {certificateConsoleOpen && (certificateAction.job || certificateAction.message) ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-console-panel" aria-label="Certificate job console">
                  <div className="section-heading">
                    <div>
                      <h3>Certificate job console</h3>
                      <ProgressConsolePrimaryLine job={certificateAction.job} summary={certificateAction.message || "No active certificate job."} />
                    </div>
                    <div className="section-actions">
                      <button className="secondary-action compact" onClick={() => void navigator.clipboard.writeText(jobConsoleText(certificateAction.job, certificateAction.message || "No certificate job events are available yet.", certificateConsoleEventText))} type="button">Copy log</button>
                      <button className="secondary-action compact" onClick={() => setCertificateConsoleOpen(false)} type="button">Close</button>
                    </div>
                  </div>
                  <pre>{jobConsoleText(certificateAction.job, certificateAction.message || "No certificate job events are available yet.", certificateConsoleEventText)}</pre>
                </section>
              </div>
            ) : null}

            {inboundBatchConsoleOpen && inboundBatchJob ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-console-panel" aria-label="Inbound batch progress console">
                  <div className="section-heading">
                    <div>
                      <h3>Inbound batch progress</h3>
                      <ProgressConsolePrimaryLine
                        job={inboundBatchJob}
                        summary={inboundBatchMessage || "Inbound channel batch."}
                      />
                    </div>
                    <div className="section-actions">
                      {inboundBatchJob && !["queued", "running", "succeeded"].includes(inboundBatchJob.status) ? (
                        <button className="secondary-action compact" onClick={retryCurrentInboundBatch} type="button">Retry unfinished</button>
                      ) : null}
                      <button className="secondary-action compact" onClick={closeInboundBatchConsole} type="button">Close</button>
                    </div>
                  </div>
                  {inboundBatchJob && Array.isArray(inboundBatchJob.input?.children) ? (
                    <div className="batch-channel-progress" aria-label="Inbound batch progress">
                      {inboundBatchJob.input.children.map((child, index) => {
                        const row = child as Record<string, unknown>;
                        const channelId = String(row.channelId || "");
                        const channel = engagementOperations?.inboundChannels.find((candidate) => candidate.channelId === channelId);
                        const retryable = ["failed", "validation_failed", "not_started"].includes(String(row.status || ""));
                        return (
                          <span key={`${channelId}-${index}`}>
                            {index + 1}. {channelId || "channel"} — {String(row.status || "queued")}
                            {retryable && channel ? <button className="danger-action compact" onClick={() => onRemoveInboundChannel(channel)} type="button">Remove</button> : null}
                          </span>
                        );
                      })}
                    </div>
                  ) : null}
                </section>
              </div>
            ) : null}

            {channelConsoleOpen && (inboundChannelAction.job || inboundChannelAction.message) ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-console-panel" aria-label="Channel job console">
                  <div className="section-heading">
                    <div>
                      <h3>Channel job console</h3>
                      <ProgressConsolePrimaryLine
                        job={inboundChannelAction.job}
                        summary={inboundChannelAction.message || "No active channel job."}
                      />
                    </div>
                    <button className="secondary-action compact" onClick={() => setChannelConsoleOpen(false)} type="button">Close</button>
                  </div>
                  <pre>{channelConsoleText(inboundChannelAction.job)}</pre>
                </section>
              </div>
            ) : null}
          </section>
        ) : null}

        {activeEngagementTab === "capabilities" ? (
          <CapabilitiesPage
            key={`${selectedEngagementId ?? "none"}:${backflipsServiceAction.job?.id ?? "no-backflips-job"}`}
            engagementId={selectedEngagementId}
            onConfigureBackflips={() => setActiveServiceComposer("backflips")}
            onConfigureStaticWeb={openWebStaticComposer}
            onConfigureCustomListener={openGenericComposer}
            staticWebActiveCount={webStaticActivePlacements.length}
            customListenerActiveCount={genericServiceActivePlacements.length}
          />
        ) : null}

        {activeServiceComposer || desktopConsoleOpen ? (
          <section className="workflow-stack" aria-label="Capability dialogs">
            {activeServiceComposer === "web-static" ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel service-floating-panel" aria-label="Static web service workflow">
                  <div className="section-heading">
                    <div>
                      <h3>Static Web</h3>
                      <p>Manage proxy-local web listeners and content paths.</p>
                    </div>
                    <div className="section-actions compact-actions">
                      <span>{webStaticServiceAction.status}</span>
                      <button className="secondary-action compact" onClick={() => setActiveServiceComposer(null)} type="button">
                        Close
                      </button>
                    </div>
                  </div>
                  <p className="guardrail-hint">Barragan creates the listener/container structure and starter index.html. Operators place website files under the content path shown for each site.</p>
                  {webStaticServiceAction.message || webStaticServiceRemovalAction.message ? (
                    <div className="inline-warning" role="status">
                      {webStaticServiceAction.message || webStaticServiceRemovalAction.message}
                    </div>
                  ) : null}
                  <div className="section-actions">
                    <button className="primary-action compact" disabled={webStaticServiceAction.status === "running"} onClick={startNewWebStaticSite} type="button">
                      Add Site
                    </button>
                  </div>
                  <div className="table-panel embedded operations-table static-web-services-table" aria-label="Static web service placements">
                    <TableHeader columns={["Site", "Proxy", "URL", "Cert", "Status", "Actions"]} />
                    {webStaticPlacements.length ? (
                      webStaticPlacements.map((placement) => {
                        const siteName = placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId) || "static-web";
                        const publicUrl = webStaticPlacementPublicUrl(placement, engagementOperations, inboundEngagementName);
                        return (
                          <div className="table-row" key={placement.serviceId ?? `${placement.hostId}-${siteName}`}>
                            <span>{siteName}</span>
                            <span>{placement.hostId || "N/A"}</span>
                            <span>
                              {publicUrl ? (
                                <a href={publicUrl} rel="noreferrer" target="_blank">{publicUrl}</a>
                              ) : (
                                "Not Published"
                              )}
                            </span>
                            <span>Not Managed</span>
                            <StatusPill value={placement.status} />
                            <span className="row-actions static-web-row-actions">
                              <button className="secondary-action compact" disabled={webStaticServiceAction.status === "running"} onClick={() => configureWebStaticSite(placement)} type="button">
                                Configure
                              </button>
                            </span>
                          </div>
                        );
                      })
                    ) : (
                      <OperationsEmptyState message="No Static Web sites are configured yet." />
                    )}
                  </div>
                  {webStaticSiteComposerOpen ? (
                    <section className="service-inline-form" aria-label="Site Configuration">
                      <div className="section-heading">
                        <div>
                          <h3>Site Configuration</h3>
                          <p>Review the website files before Apply. Existing content is preserved by default; restoring the starter page replaces only index.html.</p>
                        </div>
                      </div>
                      <div className="service-form-grid">
                        <label>
                          <span>Web proxy</span>
                          <select
                            aria-label="Web proxy"
                            disabled={webStaticServiceAction.status === "running"}
                            onChange={(event) => updateWebStaticProxy(event.target.value)}
                            value={webStaticServiceForm.proxyId}
                          >
                            {proxyOptions.map((proxy) => (
                              <option key={`web-static-proxy-${proxy}`} value={proxy}>{proxy}</option>
                            ))}
                          </select>
                        </label>
                        <label>
                          <span>Site name</span>
                          <input
                            aria-label="Web site name"
                            disabled={webStaticServiceAction.status === "running"}
                            onChange={(event) => onUpdateWebStaticServiceForm({ siteName: event.target.value })}
                            placeholder="campaign-site"
                            value={webStaticServiceForm.siteName}
                          />
                        </label>
                        <label>
                          <span>Domain</span>
                          <input
                            aria-label="Web domain"
                            disabled={webStaticServiceAction.status === "running"}
                            onChange={(event) => onUpdateWebStaticServiceForm({ domain: event.target.value })}
                            placeholder="www.example.com"
                            value={webStaticServiceForm.domain}
                          />
                        </label>
                      </div>
                      <div className="managed-port-row">
                        <div className="managed-port-item">
                          <span>Managed route</span>
                          <strong>{webStaticServiceForm.proxyId} shared front :80/:443 → site container :8081</strong>
                        </div>
                        <div className="managed-port-item content-path">
                          <span>Site Content Path</span>
                          <code>{webStaticFormContentDirectory(webStaticServiceForm)}</code>
                        </div>
                      </div>
                      {webStaticServiceAction.preview?.contentReview ? (
                        <fieldset className="site-content-review" aria-label="Website content review">
                          <legend>{webStaticServiceAction.preview.contentReview.state === "existing" ? "Existing website files found" : "Empty website directory"}</legend>
                          <p>{webStaticServiceAction.preview.contentReview.message}</p>
                          {webStaticServiceAction.preview.contentReview.state === "existing" ? (
                            <>
                              <label>
                                <input type="radio" name="web-content-action" value="preserve"
                                  checked={(webStaticServiceForm.contentAction ?? "preserve") === "preserve"}
                                  onChange={() => onUpdateWebStaticServiceForm({ contentAction: "preserve" })} />
                                <span>Preserve existing content</span>
                              </label>
                              <label>
                                <input type="radio" name="web-content-action" value="restore-starter"
                                  checked={webStaticServiceForm.contentAction === "restore-starter"}
                                  onChange={() => onUpdateWebStaticServiceForm({ contentAction: "restore-starter" })} />
                                <span>Restore the “It works!” page</span>
                              </label>
                              <p>Restore replaces only index.html. Other files and directories are kept.</p>
                            </>
                          ) : <p>The starter page will be created. Files added after review will require another review.</p>}
                        </fieldset>
                      ) : null}
                      <div className="form-actions">
                        {activeWebStaticPlacementRemoved ? (
                          <>
                          <button className="secondary-action" disabled={!webStaticApplyReady}
                            onClick={onPreviewWebStaticServiceApply} type="button">Preview Web Apply</button>
                          <button
                            className="primary-action"
                            disabled={!webStaticApplyReady || !webStaticContentReviewed}
                            onClick={restoreConfiguredWebStaticSite}
                            type="button"
                          >
                            Restore
                          </button>
                          </>
                        ) : (
                          <>
                            <button
                              className="secondary-action"
                              disabled={!webStaticApplyReady}
                              onClick={onPreviewWebStaticServiceApply}
                              type="button"
                            >
                              Preview Web Apply
                            </button>
                            <button
                              className="primary-action"
                              disabled={!webStaticApplyReady || !webStaticContentReviewed}
                              onClick={onApplyWebStaticService}
                              type="button"
                            >
                              Apply Static Web
                            </button>
                            {activeWebStaticPlacement ? (
                              <>
                                <button
                                  className="secondary-action"
                                  disabled={webStaticServiceAction.status === "running"}
                                  onClick={() => publishWebStaticSite(activeWebStaticPlacement)}
                                  type="button"
                                >
                                  Publish Through Inbound Channel
                                </button>
                                <button
                                  className="danger-action"
                                  disabled={!activeWebStaticPlacement.serviceId || webStaticServiceRemovalAction.status === "running"}
                                  onClick={() => onPreviewWebStaticServiceRemove(activeWebStaticPlacement.serviceId || "")}
                                  type="button"
                                >
                                  Remove
                                </button>
                              </>
                            ) : null}
                          </>
                        )}
                        <button className="secondary-action" onClick={() => setWebStaticSiteComposerOpen(false)} type="button">
                          Cancel
                        </button>
                      </div>
                      {activeWebStaticPlacementRemoving && webStaticServiceRemovalAction.confirmationToken ? (
                        <label className="inline-confirmation site-action-confirmation">
                          <span>Type {webStaticServiceRemovalAction.confirmationToken}</span>
                          <input
                            aria-label={`Static Web removal confirmation for ${activeWebStaticPlacement?.siteName || webStaticServiceForm.siteName}`}
                            onChange={(event) =>
                              onUpdateWebStaticServiceRemovalAction((current) => ({
                                ...current,
                                confirmation: event.target.value
                              }))
                            }
                            placeholder={webStaticServiceRemovalAction.confirmationToken}
                            value={webStaticServiceRemovalAction.confirmation}
                          />
                          <button
                            className="danger-action compact"
                            disabled={
                              webStaticServiceRemovalAction.status === "running" ||
                              webStaticServiceRemovalAction.confirmation !== webStaticServiceRemovalAction.confirmationToken
                            }
                            onClick={onApplyWebStaticServiceRemove}
                            type="button"
                          >
                            Confirm Remove
                          </button>
                        </label>
                      ) : null}
                    </section>
                  ) : null}
                  {webStaticServiceAction.preview ? (
                    <div className="detail-grid test-deploy-grid" aria-label="Static web apply preview result">
                      <div>
                        <span>Preview job</span>
                        <strong>{webStaticServiceAction.preview.job.id}</strong>
                      </div>
                      <div>
                        <span>Workspace status</span>
                        <strong>{webStaticServiceAction.preview.workspace.status}</strong>
                      </div>
                      <div>
                        <span>Content path</span>
                        <strong>{webStaticServicePath(webStaticServiceAction.preview.service, "contentPath")}</strong>
                      </div>
                      <div>
                        <span>Listener</span>
                        <strong>{webStaticServiceAction.preview.service.proxyId}:{String(webStaticServiceAction.preview.service.config.internalPort ?? "N/A")}</strong>
                      </div>
                      <div>
                        <span>Capability readiness</span>
                        <strong>{webStaticServiceAction.preview.capabilityPrerequisite?.ready ? "Ready" : "Workspace required"}</strong>
                      </div>
                      {webStaticServiceAction.preview.capabilityPrerequisite?.willSelectOnApply ? (
                        <div>
                          <span>Capability selection</span>
                          <strong>Static Web will be selected and locked before apply</strong>
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                  {webStaticServiceAction.result ? (
                    <div className="detail-grid test-deploy-grid" aria-label="Static web apply job result">
                      <div>
                        <span>Returned job</span>
                        <strong>{webStaticServiceAction.result.job.id}</strong>
                      </div>
                      <div>
                        <span>Service status</span>
                        <strong>{webStaticServiceAction.result.service.status}</strong>
                      </div>
                      <div>
                        <span>Content directory</span>
                        <strong>{webStaticServiceContentDirectory(webStaticServiceAction.result.service)}</strong>
                      </div>
                      <div>
                        <span>Next step</span>
                        <button
                          className="primary-action compact"
                          onClick={() => publishWebStaticSite(webStaticServicePlacement(webStaticServiceAction.result!.service))}
                          type="button"
                        >
                          Publish Through Inbound Channel
                        </button>
                      </div>
                    </div>
                  ) : null}
                </section>
              </div>
            ) : null}

            {activeServiceComposer === "generic" ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel service-floating-panel" aria-label="Custom Listener workflow">
                  <div className="section-heading">
                    <div>
                      <h3>Custom Listener</h3>
                      <p>Track operator-managed listeners and validation metadata for inbound routing.</p>
                    </div>
                    <div className="section-actions compact-actions">
                      <span>{genericServiceAction.status}</span>
                      <button className="primary-action compact" onClick={startNewGenericService} type="button">
                        Add Custom Listener
                      </button>
                      <button className="secondary-action compact" onClick={() => setActiveServiceComposer(null)} type="button">
                        Close
                      </button>
                    </div>
                  </div>
                  <p className="guardrail-hint">Barragan records the listener and validation contract. It does not start, stop, or execute the server process.</p>
                  {genericServiceAction.message ? (
                    <div className="inline-warning" role="status">
                      {genericServiceAction.message}
                    </div>
                  ) : null}
                  <div className="table-panel embedded operations-table static-web-services-table" aria-label="Custom Listener configurations">
                    <TableHeader columns={["Listener", "Host", "Endpoint", "Validation", "Status", "Actions"]} />
                    {genericServicePlacements.length ? (
                      genericServicePlacements.map((placement) => (
                        <div className="table-row" key={placement.serviceId ?? `${placement.hostId}-${placement.port}`}>
                          <span>{placement.service || placement.serviceId}</span>
                          <span>{placement.hostId || "N/A"}</span>
                          <span>{placement.port ? `${String(placement.protocol || "tcp").toUpperCase()} ${placement.port}` : "N/A"}</span>
                          <span>{placement.validationProfile?.label || placement.validationProfile?.type || "Basic reachability"}</span>
                          <StatusPill value={placement.status} />
                          <span className="row-actions static-web-row-actions">
                            <button className="secondary-action compact" onClick={() => configureGenericService(placement)} type="button">
                              Configure
                            </button>
                          </span>
                        </div>
                      ))
                    ) : (
                      <OperationsEmptyState message="No Custom Listeners are tracked yet." />
                    )}
                  </div>
                  {genericServiceEditorOpen ? (
                    <div className="modal-scrim nested-modal-scrim" role="presentation">
                      <section className="floating-panel service-config-floating-panel" aria-label="Custom Listener Configuration">
                        <div className="section-heading">
                          <div>
                            <h3>{genericServiceForm.serviceId ? "Configure Custom Listener" : "Add Custom Listener"}</h3>
                            <p>Use this for ad-hoc services that operators manage outside Barragan.</p>
                          </div>
                          <button className="secondary-action compact" onClick={() => setGenericServiceEditorOpen(false)} type="button">
                            Cancel
                          </button>
                        </div>
                        <div className="service-form-grid">
                          <label>
                            <span>Name</span>
                            <input aria-label="Custom Listener name" onChange={(event) => onUpdateGenericServiceForm({ name: event.target.value })} placeholder="inventory listener" value={genericServiceForm.name} />
                          </label>
                          <label>
                            <span>Host</span>
                            <select aria-label="Custom Listener host" onChange={(event) => onUpdateGenericServiceForm({ targetHost: event.target.value })} value={genericServiceForm.targetHost}>
                              <option value="homebase">homebase</option>
                              {proxyOptions.map((proxy) => (
                                <option key={`generic-host-${proxy}`} value={proxy}>{proxy}</option>
                              ))}
                            </select>
                          </label>
                          <label>
                            <span>Protocol</span>
                            <select aria-label="Custom Listener protocol" onChange={(event) => onUpdateGenericServiceForm({ protocol: event.target.value })} value={genericServiceForm.protocol}>
                              <option value="tcp">TCP</option>
                              <option value="http">HTTP</option>
                              <option value="https">HTTPS</option>
                              <option value="udp">UDP</option>
                            </select>
                          </label>
                          <label>
                            <span>Internal port</span>
                            <input aria-label="Custom Listener internal port" onChange={(event) => onUpdateGenericServiceForm({ internalPort: event.target.value })} placeholder="18090" value={genericServiceForm.internalPort} />
                          </label>
                          <label className="wide-field">
                            <span>Server script or binary path</span>
                            <input aria-label="Custom Listener script path" onChange={(event) => onUpdateGenericServiceForm({ scriptPath: event.target.value })} placeholder="/opt/tools/server.py" value={genericServiceForm.scriptPath ?? ""} />
                          </label>
                          <label className="wide-field">
                            <span>Purpose</span>
                            <input aria-label="Custom Listener purpose" onChange={(event) => onUpdateGenericServiceForm({ purpose: event.target.value })} placeholder="temporary engagement tool" value={genericServiceForm.purpose ?? ""} />
                          </label>
                          <label className="wide-field">
                            <span>Tags</span>
                            <input aria-label="Custom Listener tags" onChange={(event) => onUpdateGenericServiceForm({ tags: genericTagsFromText(event.target.value) })} placeholder="c2, test, inventory" value={(genericServiceForm.tags ?? []).join(", ")} />
                          </label>
                          <label className="wide-field">
                            <span>Notes</span>
                            <textarea aria-label="Custom Listener notes" onChange={(event) => onUpdateGenericServiceForm({ notes: event.target.value })} placeholder="Operator-managed process details" value={genericServiceForm.notes ?? ""} />
                          </label>
                        </div>
                        <details className="advanced-settings-panel compact-advanced">
                          <summary>Advanced validation</summary>
                          <div className="service-form-grid">
                            <label>
                              <span>Validation</span>
                              <select
                                aria-label="Custom Listener validation"
                                onChange={(event) => onUpdateGenericServiceForm({ validationProfile: { type: event.target.value as InboundValidationProfileType, label: validationProfileLabel(event.target.value) } })}
                                value={genericServiceForm.validationProfile?.type ?? defaultValidationProfileForGenericProtocol(genericServiceForm.protocol).type}
                              >
                                <option value="tcp-connect">TCP reachability</option>
                                <option value="tcp-send-receive">TCP send/expect</option>
                                <option value="http">HTTP check</option>
                                <option value="udp-send-receive">UDP send/expect</option>
                                <option value="manual">Manual / no app probe</option>
                              </select>
                            </label>
                            <label>
                              <span>Request text</span>
                              <input
                                aria-label="Custom Listener validation request"
                                onChange={(event) => onUpdateGenericServiceForm({ validationProfile: { ...(genericServiceForm.validationProfile ?? defaultValidationProfileForGenericProtocol(genericServiceForm.protocol)), requestText: event.target.value } })}
                                value={genericServiceForm.validationProfile?.requestText ?? ""}
                              />
                            </label>
                            <label>
                              <span>Expected response</span>
                              <input
                                aria-label="Custom Listener validation expected response"
                                onChange={(event) => onUpdateGenericServiceForm({ validationProfile: { ...(genericServiceForm.validationProfile ?? defaultValidationProfileForGenericProtocol(genericServiceForm.protocol)), expectedResponse: event.target.value } })}
                                value={genericServiceForm.validationProfile?.expectedResponse ?? ""}
                              />
                            </label>
                          </div>
                        </details>
                        <div className="form-actions">
                          <button className="primary-action" disabled={!genericServiceReady(genericServiceForm) || genericServiceAction.status === "saving"} onClick={onSaveGenericService} type="button">
                            Save Custom Listener
                          </button>
                          {activeGenericServicePlacement?.status === "Active" ? (
                            <>
                              <button className="secondary-action" onClick={() => publishGenericService(activeGenericServicePlacement)} type="button">
                                Publish Through Inbound Channel
                              </button>
                              <button className="secondary-action" onClick={() => onDisableGenericService(activeGenericServicePlacement.serviceId || "")} type="button">
                                Disable configuration
                              </button>
                              <button className="danger-action" onClick={() => onRemoveGenericService(activeGenericServicePlacement.serviceId || "")} type="button">
                                Remove configuration
                              </button>
                            </>
                          ) : null}
                          {activeGenericServicePlacement && activeGenericServicePlacement.status !== "Active" ? (
                            <>
                              <button className="secondary-action" onClick={() => onRestoreGenericService(activeGenericServicePlacement.serviceId || "")} type="button">
                                Restore configuration
                              </button>
                              {activeGenericServicePlacement.status !== "Removed" ? (
                                <button className="danger-action" onClick={() => onRemoveGenericService(activeGenericServicePlacement.serviceId || "")} type="button">
                                  Remove configuration
                                </button>
                              ) : null}
                            </>
                          ) : null}
                        </div>
                      </section>
                    </div>
                  ) : null}
                </section>
              </div>
            ) : null}

            {desktopConsoleOpen && desktopConsoleAvailable ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-console-panel" aria-label="Desktop job console">
                  <div className="section-heading">
                    <div>
                      <h3>Desktop progress console</h3>
                      <ProgressConsolePrimaryLine job={desktopServiceAction.job} summary={desktopServiceAction.message || "Desktop service job progress."} />
                    </div>
                    <div className="section-actions compact-actions">
                      <button
                        className="secondary-action compact"
                        disabled={!navigator.clipboard}
                        onClick={() => {
                          if (!navigator.clipboard) {
                            return;
                          }
                          void navigator.clipboard.writeText(desktopConsoleLog).then(() => setDesktopConsoleCopied(true));
                        }}
                        type="button"
                      >
                        <Copy size={14} />
                        {desktopConsoleCopied ? "Copied" : "Copy log"}
                      </button>
                      <button className="secondary-action compact" onClick={() => setDesktopConsoleOpen(false)} type="button">
                        Close
                      </button>
                    </div>
                  </div>
                  <pre>{desktopConsoleLog}</pre>
                </section>
              </div>
            ) : null}

            {activeServiceComposer === "backflips" ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel service-floating-panel" aria-label="Backflips V2 capability workflow">
                  <div className="section-heading">
                    <div>
                      <h3>Backflips V2</h3>
                      <p>Install role and configuration prerequisites for operator-managed Backflips listeners.</p>
                    </div>
                    <div className="section-actions compact-actions">
                      <span>{backflipsServiceAction.status}</span>
                      {backflipsConsoleAvailable ? (
                        <button
                          className="secondary-action compact icon-action"
                          onClick={() => {
                            setBackflipsConsoleCopied(false);
                            setBackflipsConsoleOpen(true);
                          }}
                          title="Open Backflips progress console"
                          type="button"
                        >
                          <ListChecks size={14} />
                          <span>Log</span>
                        </button>
                      ) : null}
                      <button className="secondary-action compact" onClick={() => setActiveServiceComposer(null)} type="button">
                        Close
                      </button>
                    </div>
                  </div>
                  <p className="guardrail-hint">
                    Barragan applies <code>backflips_v2</code>, installs the engagement transport identity, and configures the default middle. Operators manage listeners afterward with <code>/opt/backflips/sshbackflip.py</code> on the proxy.
                  </p>
                  {backflipsServiceAction.message ? (
                    <div className="inline-warning" role="status">
                      {backflipsServiceAction.message}
                    </div>
                  ) : null}
                  <div className="detail-grid test-deploy-grid">
                    <label>
                      <span>Backflips proxy</span>
                      <select
                        aria-label="Backflips proxy"
                        disabled={backflipsServiceAction.status === "running"}
                        onChange={(event) => {
                          const proxyId = event.target.value;
                          onUpdateBackflipsServiceAction({
                            proxyId,
                            preview: null,
                            job: null,
                            message: ""
                          });
                        }}
                        value={backflipsServiceAction.proxyId}
                      >
                        {proxyOptions.map((proxy) => (
                          <option key={`backflips-proxy-${proxy}`} value={proxy}>{proxy}</option>
                        ))}
                      </select>
                    </label>
                    <button
                      className="secondary-action"
                      disabled={!selectedEngagementId || backflipsServiceAction.status === "running"}
                      onClick={onPreviewBackflipsServiceApply}
                      type="button"
                    >
                      Preview Prerequisites
                    </button>
                    <label>
                      <span>Type {backflipsConfirmationToken}</span>
                      <input
                        aria-label="Backflips confirmation"
                        onChange={(event) => onUpdateBackflipsServiceAction({ confirmation: event.target.value })}
                        placeholder={backflipsConfirmationToken}
                        value={backflipsServiceAction.confirmation}
                      />
                    </label>
                    <button
                      className="primary-action"
                      disabled={!backflipsApplyReady}
                      onClick={onApplyBackflipsService}
                      type="button"
                    >
                      Apply Backflips Prerequisites
                    </button>
                  </div>
                  <p className="helper-text">
                    New edges inherit the required remote-forward SSH settings during sketch deployment. Listener lifecycle stays in the Backflips CLI so operators do not need to return to Barragan.
                  </p>
                </section>
              </div>
            ) : null}

            {backflipsConsoleOpen && backflipsConsoleAvailable ? (
              <div className="modal-scrim" role="presentation">
                <section className="floating-panel channel-console-panel" aria-label="Backflips job console">
                  <div className="section-heading">
                    <div>
                      <h3>Backflips progress console</h3>
                      <ProgressConsolePrimaryLine job={backflipsServiceAction.job} summary={backflipsServiceAction.message || "Backflips job progress."} />
                    </div>
                    <div className="section-actions compact-actions">
                      <button
                        className="secondary-action compact"
                        disabled={!navigator.clipboard}
                        onClick={() => {
                          if (!navigator.clipboard) {
                            return;
                          }
                          void navigator.clipboard.writeText(backflipsConsoleLog).then(() => setBackflipsConsoleCopied(true));
                        }}
                        type="button"
                      >
                        <Copy size={14} />
                        {backflipsConsoleCopied ? "Copied" : "Copy log"}
                      </button>
                      <button className="secondary-action compact" onClick={() => setBackflipsConsoleOpen(false)} type="button">
                        Close
                      </button>
                    </div>
                  </div>
                  <pre>{backflipsConsoleLog}</pre>
                </section>
              </div>
            ) : null}

          </section>
        ) : null}

        {activeEngagementTab === "history" ? (
          <section className="workflow-stack" aria-label="Engagement history">
            <section className="pilot-run-history" aria-label="Core deployment history">
              <div className="section-heading">
                <h3>Core deployment history</h3>
                <div className="section-actions">
                  <span>{testDeployRunJob?.status ?? "no deployment run selected"}</span>
                  {testDeployRunJob ? (
                    <button className="secondary-action compact" onClick={onRefreshTestDeploymentRun} type="button">
                      Refresh
                    </button>
                  ) : null}
                </div>
              </div>
              {testDeployRunJob ? (
                <ol className="event-list">
                  {testDeployRunJob.events.map((event) => (
                    <li className={`event-row ${event.level}`} key={`history-core-${event.sequence}`}>
                      <span>{event.sequence}</span>
                      <strong>{event.message}</strong>
                      <code>{eventDataSummary(event.data)}</code>
                    </li>
                  ))}
                </ol>
              ) : (
                <div className="empty-state inline">
                  <h3>No run history loaded</h3>
                  <p>Deployment jobs for this engagement will appear here.</p>
                </div>
              )}
            </section>

            <section className="pilot-run-history" aria-label="Sketch deployment history">
              <div className="section-heading">
                <h3>Sketch deployment history</h3>
                <div className="section-actions">
                  <span>{linodeSketchRunJob?.status ?? "no sketch run selected"}</span>
                  {linodeSketchRunJob ? (
                    <button className="secondary-action compact" onClick={onRefreshLinodeSketchRun} type="button">
                      Refresh
                    </button>
                  ) : null}
                </div>
              </div>
              {linodeSketchRunJob ? (
                <ol className="event-list">
                  {linodeSketchRunJob.events.map((event) => (
                    <li className={`event-row ${event.level}`} key={`history-sketch-${event.sequence}`}>
                      <span>{event.sequence}</span>
                      <strong>{event.message}</strong>
                      <code>{eventDataSummary(event.data)}</code>
                    </li>
                  ))}
                </ol>
              ) : (
                <div className="empty-state inline">
                  <h3>No sketch run history loaded</h3>
                  <p>Sketch deployment jobs for this engagement will appear here.</p>
                </div>
              )}
            </section>

            <section className="revision-history" aria-label="Deployment plan history">
              <div className="section-heading">
                <h3>Deployment plan history</h3>
                <div className="section-actions">
                  <span>{revisionHistoryStatus}</span>
                  <button
                    className="secondary-action compact"
                    disabled={!selectedEngagementId || revisionHistoryStatus === "loading"}
                    onClick={onLoadSelectedRevisions}
                    type="button"
                  >
                    {revisionHistoryStatus === "loading" ? "Loading" : "Load Plans"}
                  </button>
                </div>
              </div>
              {revisionHistoryStatus === "error" ? (
                <div className="empty-state inline">
                  <h3>Plans unavailable</h3>
                  <p>The deployment plan API did not return a successful response.</p>
                </div>
              ) : null}
              {revisionHistory.length > 0 ? (
                <div className="revision-list">
                  {revisionHistory.map((revision) => (
                    <button
                      className={revision.id === selectedRevisionId ? "revision-item selected" : "revision-item"}
                      key={revision.id}
                      onClick={() => setSelectedRevisionId(revision.id)}
                      type="button"
                    >
                      <div>
                        <span>Plan {revision.revisionNumber}</span>
                        <strong>{revision.id}</strong>
                      </div>
                      <span>{revision.status}</span>
                      <span>{topologySummary(revision)}</span>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="empty-state inline">
                  <h3>No plans loaded</h3>
                  <p>Select an engagement and load saved deployment plans.</p>
                </div>
              )}
            </section>

            {selectedRevision ? (
              <section className="revision-detail" aria-label="Deployment plan details">
                <div className="section-heading">
                  <h3>Deployment plan details</h3>
                  <div className="section-actions">
                    <span>{selectedRevision.status}</span>
                    <button
                      className="secondary-action compact"
                      disabled={revisionRenderStatus === "rendering"}
                      onClick={onRenderSelectedRevision}
                      type="button"
                    >
                      {revisionRenderStatus === "rendering" ? "Generating" : "Generate IaC Files"}
                    </button>
                  </div>
                </div>
                <div className="detail-grid">
                  <div>
                    <span>Plan ID</span>
                    <strong>{selectedRevision.id}</strong>
                  </div>
                  <div>
                    <span>Topology</span>
                    <strong>{topologySummary(selectedRevision)}</strong>
                  </div>
                  <div>
                    <span>Planned actions</span>
                    <strong>{selectedRevision.runIntent.length} steps</strong>
                  </div>
                  <div>
                    <span>Safety checks</span>
                    <strong>{validationGateSummary(selectedRevision)}</strong>
                  </div>
                  <div>
                    <span>Artifacts</span>
                    <strong>{revisionRenderResult ? `${revisionRenderResult.artifacts.length} files` : revisionRenderStatus}</strong>
                  </div>
                </div>
                {selectedRevision.validationGates?.length > 0 ? (
                  <div className="validation-gates" aria-label="Safety checks">
                    {selectedRevision.validationGates.map((gate) => (
                      <div className={`validation-gate ${gate.status}`} key={gate.id}>
                        <div>
                          <strong>{gate.label}</strong>
                          <span>{gate.message}</span>
                        </div>
                        <span>{gate.status}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state inline">
                    <h3>No safety checks</h3>
                    <p>This deployment plan did not include deploy-readiness validation data.</p>
                  </div>
                )}
                {revisionRenderStatus === "error" ? (
                  <div className="empty-state inline">
                    <h3>Render failed</h3>
                    <p>The render API did not return a successful response.</p>
                  </div>
                ) : null}
                {revisionRenderResult ? (
                  <div className="render-result">
                    <span>Render root</span>
                    <strong>{revisionRenderResult.root}</strong>
                  </div>
                ) : null}
                {selectedRevision.runIntent.length > 0 ? (
                  <ol className="run-intent-list">
                    {selectedRevision.runIntent.map((step, index) => (
                      <li key={`${selectedRevision.id}-intent-${index}`}>
                        <span>{String(step.step ?? `step-${index + 1}`)}</span>
                        <strong>{String(step.mutation ?? false)}</strong>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div className="empty-state inline">
                    <h3>No planned actions</h3>
                    <p>This deployment plan did not include planned action steps.</p>
                  </div>
                )}
              </section>
            ) : null}
          </section>
        ) : null}

        {activeEngagementTab === "team" ? (
          <EngagementTeamPanel engagementId={selectedEngagementId} />
        ) : null}

        {activeEngagementTab === "settings" ? (
          <section className="workflow-stack" aria-label="Engagement settings">
            <div className="filter-tabs settings-tabs" aria-label="Settings section">
              <button className={activeSettingsTab === "general" ? "active" : ""} onClick={() => setActiveSettingsTab("general")} type="button">
                General
              </button>
              <button className={activeSettingsTab === "inspector" ? "active" : ""} onClick={() => setActiveSettingsTab("inspector")} type="button">
                Inspector
              </button>
            </div>

            {activeSettingsTab === "general" ? (
              <section className="guided-review" aria-label="Engagement metadata settings">
                <div className="section-heading">
                  <h3>Settings</h3>
                  <span>{selectedEngagement?.id ?? "draft"}</span>
                </div>
                <div className="detail-grid">
                  <div>
                    <span>Name</span>
                    <strong>{selectedEngagement?.name ?? guidedEngagementName}</strong>
                  </div>
                  <div>
                    <span>Owner</span>
                    <strong>{selectedEngagement?.owner ?? guidedOperatorsList[0] ?? "unassigned"}</strong>
                  </div>
                  <div>
                    <span>Template</span>
                    <strong>standard-rti</strong>
                  </div>
                  <div>
                    <span>Archive</span>
                    <strong>managed globally</strong>
                  </div>
                  <div>
                    <span>Delete</span>
                    <strong>soft delete globally</strong>
                  </div>
                </div>
              </section>
            ) : null}

            {activeSettingsTab === "inspector" ? (
              <InspectorSettingsPanel
                observerCheckAction={observerCheckAction}
                observerForbiddenPortsInput={observerForbiddenPortsInput}
                observerSettings={observerSettings}
                onEnsureInspectorReadiness={onEnsureInspectorReadiness}
                onInspectorCleanupComplete={onInspectorCleanupComplete}
                onRunObserverCheck={onRunObserverCheck}
                onSaveObserverSettings={onSaveObserverSettings}
                onUpdateObserverSettingsDraft={onUpdateObserverSettingsDraft}
                onRetryProviderCatalogs={onEnsureProviderCatalogs}
                providerCatalogs={providerCatalogs}
                providerCatalogStatus={providerCatalogStatus}
                engagementId={selectedEngagementId}
                keyedInspectorLinodeOnly={selectedEngagement?.sketchStateSchema === "provider-keyed-v2"}
                setObserverForbiddenPortsInput={setObserverForbiddenPortsInput}
              />
            ) : null}
          </section>
        ) : null}

        {infrastructureConsoleVisible ? (
          <div className="modal-scrim" role="presentation">
            <section className="floating-panel job-console-panel deployment-job-console" aria-label={infrastructureConsoleTitle}>
              <div className="section-heading deployment-console-header">
                <div>
                  <h3>{infrastructureConsoleTitle}</h3>
                  <ProgressConsolePrimaryLine
                    activeTask={infrastructureConsoleCurrentTask(infrastructureCommandActivity, activeInfrastructureStep?.label)}
                    job={teardownAwaitingParent ? null : testDeployRunJob}
                    summary={infrastructureConsoleSummary}
                  />
                </div>
                <button className="secondary-action compact" onClick={() => setInfrastructureConsoleOpen(false)} type="button">
                  Close
                </button>
              </div>
              <pre
                ref={(node) => {
                  if (node && (testDeployRunJob?.status === "running" || testDeployTeardownStatus === "running")) {
                    node.scrollTop = node.scrollHeight;
                  }
                }}
              >
                {teardownAwaitingParent ? infrastructureConsoleSummary : infrastructureConsoleText(
                  testDeployRunJob,
                  infrastructureConsoleEmptyText,
                  visibleInfrastructureActivitySteps
                )}
              </pre>
              <footer className="deployment-console-footer">
                <span>Elapsed: {teardownAwaitingParent ? "not reported" : publishedClock ? publishedClock.elapsedSeconds === null ? "not reported" : formatActivityDuration(publishedClock.elapsedSeconds) : formatActivityDuration(infrastructureCommandActivity?.elapsedSeconds ?? 0)}</span>
                <span>Last activity: {teardownAwaitingParent ? "not reported" : publishedClock ? publishedClock.lastActivitySeconds === null ? "not reported" : `${formatActivityDuration(publishedClock.lastActivitySeconds)} ago` : `${formatActivityDuration(infrastructureCommandActivity?.lastActivitySeconds ?? 0)} ago`}</span>
                <span>{infrastructureConsoleSummary}</span>
              </footer>
            </section>
          </div>
        ) : null}
      </section>
    );
  }

  if (activeView === "jobs") {
    const firstVisibleJob = jobsPagination.total && data.jobs.length ? jobsPagination.offset + 1 : 0;
    const lastVisibleJob = jobsPagination.offset + data.jobs.length;
    return (
      <section className="workflow-view" aria-label="Jobs">
        <section className="workflow-panel">
          <div>
            <p className="eyebrow">Operations</p>
            <h3>Job History</h3>
            <p>
              {jobsStatus === "loading"
                ? "Loading job summaries."
                : `Showing ${firstVisibleJob}-${lastVisibleJob} of ${jobsPagination.total} jobs.`}
            </p>
          </div>
          <div className="section-actions">
            <button
              className="secondary-action compact"
              disabled={jobsStatus === "loading" || jobsPagination.offset === 0}
              onClick={() => onLoadJobsPage(jobsPagination.offset - jobsPagination.limit)}
              type="button"
            >
              Previous
            </button>
            <button
              className="secondary-action compact"
              disabled={jobsStatus === "loading" || !jobsPagination.hasMore}
              onClick={() => onLoadJobsPage(jobsPagination.offset + jobsPagination.limit)}
              type="button"
            >
              Next
            </button>
            <button
              className="secondary-action compact"
              disabled={jobsStatus === "loading"}
              onClick={() => onLoadJobsPage(jobsPagination.offset)}
              type="button"
            >
              Refresh
            </button>
          </div>
        </section>

        {jobsStatus === "error" ? (
          <div className="empty-state inline">
            <h3>Job history unavailable</h3>
            <p>The job summary API did not return a successful response.</p>
          </div>
        ) : null}

        <div className="table-panel embedded">
          <TableHeader columns={["Action", "Target", "Status", "Created"]} />
          {data.jobs.map((job) => (
            <button
              aria-label={`Select job ${job.id}`}
              className={selectedJobDetail?.id === job.id ? "table-row selectable selected" : "table-row selectable"}
              key={job.id}
              onClick={() => onSelectJob(job.id)}
              type="button"
            >
              <span>{job.action}</span>
              <span>{job.target}</span>
              <span>{job.status}</span>
              <span>{new Date(job.createdAt).toLocaleString()}</span>
            </button>
          ))}
        </div>

        {selectedJobDetailStatus === "loading" ? (
          <div className="empty-state inline">
            <h3>Loading job</h3>
            <p>Fetching persisted job detail.</p>
          </div>
        ) : null}

        {selectedJobDetailStatus === "error" ? (
          <div className="empty-state inline">
            <h3>Job unavailable</h3>
            <p>The job detail API did not return a successful response.</p>
          </div>
        ) : null}

        {selectedJobDetail ? (
          <section className="pilot-run-history" aria-label="Job detail">
            <div className="section-heading">
              <h3>Job detail</h3>
              <div className="section-actions">
                <span>{selectedJobDetail.status}</span>
                <button className="secondary-action compact" onClick={() => onSelectJob(selectedJobDetail.id)} type="button">
                  Refresh
                </button>
                {selectedJobDetail.action === "pilot_standard_rti_guarded_execute" || (
                  (isRecoverableEngagementTeardownJob(selectedJobDetail, engagementOperations) || hasSealedInitialCleanup(selectedJobDetail)) &&
                  data.engagements.some((engagement) => engagement.id === jobEngagementId(selectedJobDetail))
                ) ? (
                  <button
                    className="secondary-action compact"
                    onClick={() => onResumePilotRunFromJob(selectedJobDetail)}
                    type="button"
                  >
                    {hasSealedInitialCleanup(selectedJobDetail) ? "Open Engagement" : isEngagementTeardownAction(selectedJobDetail.action) ? "Resume Cleanup" : "Load In Engagement"}
                  </button>
                ) : null}
              </div>
            </div>
            <div className="detail-grid test-deploy-grid">
              <div>
                <span>Job ID</span>
                <strong>{selectedJobDetail.id}</strong>
              </div>
              <div>
                <span>Action</span>
                <strong>{selectedJobDetail.action}</strong>
              </div>
              <div>
                <span>Target</span>
                <strong>{selectedJobDetail.targetId}</strong>
              </div>
              <div>
                <span>Requested by</span>
                <strong>{selectedJobDetail.requestedBy}</strong>
              </div>
              <div>
                <span>Input</span>
                <strong>{jobRecordSummary(selectedJobDetail.input)}</strong>
              </div>
              <div>
                <span>Artifacts</span>
                <strong>{selectedJobDetail.artifactRefs.length ? selectedJobDetail.artifactRefs.join(", ") : "none"}</strong>
              </div>
            </div>
            <ol className="event-list">
              {selectedJobDetail.events.map((event) => (
                <li className={`event-row ${event.level}`} key={event.sequence}>
                  <span>{event.sequence}</span>
                  <strong>{event.message}</strong>
                  <code>{eventDataSummary(event.data)}</code>
                </li>
              ))}
            </ol>
          </section>
        ) : null}
      </section>
    );
  }

  if (activeView === "settings") {
    return (
      <section className="workflow-view" aria-label="Global Settings">
        <div className="filter-tabs settings-tabs" aria-label="Global Settings sections">
          <button className={activeGlobalSettingsTab === "user" ? "active" : ""} onClick={() => setActiveGlobalSettingsTab("user")} type="button">
            User
          </button>
          {isAdministrator ? (
            <>
              <button className={activeGlobalSettingsTab === "cloud-providers" ? "active" : ""} onClick={() => setActiveGlobalSettingsTab("cloud-providers")} type="button">
                Cloud Providers
              </button>
              <button className={activeGlobalSettingsTab === "barragan-app" ? "active" : ""} onClick={() => setActiveGlobalSettingsTab("barragan-app")} type="button">
                Barragan App
              </button>
            </>
          ) : null}
        </div>
        {activeGlobalSettingsTab === "user" ? (
          <section className="guided-review user-settings" aria-label="User settings">
            <div className="section-heading">
              <div>
                <h3>User</h3>
                <p>Manage your Barragan password and active sessions.</p>
              </div>
            </div>
            <div className="detail-grid user-settings-identity">
              <div>
                <span>Signed in as</span>
                <strong>{currentUser?.displayName || currentUser?.username || "Local development user"}</strong>
              </div>
              <div>
                <span>Username</span>
                <strong>{currentUser?.username || "authentication bypass"}</strong>
              </div>
              <div>
                <span>Access level</span>
                <strong>{isAdministrator ? "Administrator" : "Read only"}</strong>
              </div>
            </div>
            {currentUser ? (
              <div className="workflow-actions user-settings-actions">
                <button className="primary-action" onClick={onChangePassword} type="button">Change password</button>
                <button className="secondary-action" onClick={onSignOut} type="button">Sign out</button>
                <button className="danger-action" onClick={onSignOutAll} type="button">Sign out all sessions and tokens</button>
              </div>
            ) : (
              <p className="guardrail-hint">Account controls are available when local authentication is enabled.</p>
            )}
          </section>
        ) : null}
        {activeGlobalSettingsTab === "cloud-providers" && isAdministrator ? (
          <>
        <section className="guided-review" aria-label="Provider credentials">
          <div className="section-heading">
            <div>
              <h3>Provider credentials</h3>
              <p>Manage encrypted API token aliases for sketch and registrar providers.</p>
            </div>
            <div className="section-actions">
              <span>{credentialsStatus}</span>
              <button className="secondary-action compact" onClick={() => void onRefreshCredentials()} type="button">
                Refresh
              </button>
            </div>
          </div>
          <section className="guided-form infrastructure-form" aria-label="Credential form">
            <label>
              <span>Provider</span>
              <select
                aria-label="Credential provider"
                onChange={(event) => setCredentialForm({ ...credentialForm, provider: event.target.value })}
                value={credentialForm.provider}
              >
                {credentialProviderOptions.map((provider) => (
                  <option key={provider} value={provider}>{provider}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Alias</span>
              <input
                aria-label="Credential alias"
                onChange={(event) => setCredentialForm({ ...credentialForm, alias: event.target.value })}
                placeholder="linode-barragan"
                value={credentialForm.alias}
              />
            </label>
            <label>
              <span>Description</span>
              <input
                aria-label="Credential description"
                onChange={(event) => setCredentialForm({ ...credentialForm, description: event.target.value })}
                placeholder="Linode sketch token"
                value={credentialForm.description}
              />
            </label>
            <label>
              <span>Secret value</span>
              <input
                aria-label="Credential secret"
                onChange={(event) => setCredentialForm({ ...credentialForm, secret: event.target.value })}
                placeholder="Paste token to save or rotate"
                type="password"
                value={credentialForm.secret}
              />
            </label>
          </section>
          <div className="workflow-actions">
            <button
              className="primary-action"
              disabled={credentialsStatus === "saving" || !credentialForm.alias || !credentialForm.secret}
              onClick={onCreateCredential}
              type="button"
            >
              Save Credential
            </button>
          </div>
          {credentialMessage ? <p role="status">{credentialMessage}</p> : null}
          <div className="table-panel embedded operations-table" aria-label="Credential aliases">
            <TableHeader columns={["Provider", "Alias", "Default", "Status", "Description", "Updated", "Actions"]} />
            {credentials.length ? (
              credentials.map((credential) => (
                <div className="table-row" key={credential.id}>
                  <span>{credential.provider}</span>
                  <span>{credential.alias}</span>
                  <span>{credential.isDefault ? "Default" : "No"}</span>
                  <StatusPill value={credential.status} />
                  <span>{credential.description || "N/A"}</span>
                  <span>{new Date(credential.updatedAt).toLocaleString()}</span>
                  <span className="section-actions">
                    <button
                      className="secondary-action compact"
                      disabled={credential.status !== "active" || credential.isDefault}
                      onClick={() => onSetDefaultCredential(credential.id)}
                      type="button"
                    >
                      Set Default
                    </button>
                    <button className="secondary-action compact" onClick={() => onValidateCredential(credential.id)} type="button">
                      Test
                    </button>
                    <button className="secondary-action compact" onClick={() => onRotateCredential(credential)} type="button">
                      Rotate
                    </button>
                    <button className="secondary-action compact danger" onClick={() => onDisableCredential(credential.id)} type="button">
                      Disable
                    </button>
                  </span>
                </div>
              ))
            ) : (
              <OperationsEmptyState message="No provider credential aliases have been saved yet." />
            )}
          </div>
        </section>
        <section className="guided-review" aria-label="Sketch region allowlist">
          <div className="section-heading">
            <div>
              <h3>Sketch region allowlist</h3>
              <p>Control which provider regions operators can select for middle and edge nodes.</p>
            </div>
            <div className="section-actions">
              <span>{providerRegionPolicyStatus}</span>
              <button className="secondary-action compact" disabled={providerRegionPolicyStatus === "loading" || providerRegionPolicyStatus === "saving"} onClick={() => void onRefreshProviderRegionPolicies()} type="button">
                Refresh
              </button>
            </div>
          </div>
          <p className="guardrail-hint">Infrastructure dropdowns only show checked regions. Live deploy guardrails use this same policy.</p>
          {providerRegionPolicyMessage ? <p role="status">{providerRegionPolicyMessage}</p> : null}
          <div className="provider-region-policy-grid">
            {sketchProviderOptions.map((provider) => {
              const catalog = providerCatalog(providerRegionPolicyCatalogs, provider);
              const policy = providerRegionPolicies[provider];
              const allowedRegions = policy?.allowedRegions ?? catalog.regionPolicy?.allowedRegions ?? [];
              return (
                <section className="table-panel embedded provider-region-policy" aria-label={`${provider} allowed sketch regions`} key={provider}>
                  <div className="section-heading table-section-heading">
                    <div>
                      <h4>{provider}</h4>
                      <p>{allowedRegions.length} allowed · catalog {catalog.source}</p>
                    </div>
                  </div>
                  {catalog.regions.length ? (
                    catalog.regions.map((region) => (
                      <label className="checkbox-row provider-region-row" key={`${provider}-${region.id}`}>
                        <input
                          aria-label={`${provider} ${region.id}`}
                          checked={allowedRegions.includes(region.id)}
                          disabled={providerRegionPolicyStatus !== "ready"}
                          onChange={(event) => onUpdateProviderRegionPolicy(provider, region.id, event.target.checked)}
                          type="checkbox"
                        />
                        <span>
                          <strong>{region.label || region.id}</strong>
                          <small>{region.id}{region.available ? "" : " · unavailable"}</small>
                        </span>
                      </label>
                    ))
                  ) : (
                    <OperationsEmptyState message="No provider regions are available from the current catalog." />
                  )}
                </section>
              );
            })}
          </div>
        </section>
        <section className="guided-review" aria-label="DigitalOcean sketch readiness">
          <div className="section-heading">
            <div>
              <h3>DigitalOcean sketch readiness</h3>
              <p>Check whether DigitalOcean sketch deployment can use the approved test region and size before any live mutation.</p>
            </div>
            <div className="section-actions">
              <StatusPill value={digitalOceanPreflightAction.result?.ready ? "Ready" : digitalOceanPreflightAction.status === "idle" ? "Not Checked" : "Not Ready"} />
              <button
                className="secondary-action compact"
                disabled={digitalOceanPreflightAction.status === "running"}
                onClick={onRunDigitalOceanSketchPreflight}
                type="button"
              >
                Check DigitalOcean Sketch Readiness
              </button>
            </div>
          </div>
          <p className="guardrail-hint">This preflight reads DigitalOcean catalog metadata only. It does not create resources or contact sketch middle or edge nodes.</p>
          {digitalOceanPreflightAction.message ? (
            <div className="inline-warning" role="status">
              {digitalOceanPreflightAction.message}
            </div>
          ) : null}
          {digitalOceanPreflightAction.result ? (
            <div className="detail-grid test-deploy-grid" aria-label="DigitalOcean preflight result">
              <div>
                <span>Provider</span>
                <strong>{digitalOceanPreflightAction.result.provider}</strong>
              </div>
              <div>
                <span>Ready</span>
                <strong>{digitalOceanPreflightAction.result.ready ? "Yes" : "No"}</strong>
              </div>
              <div>
                <span>Catalog source</span>
                <strong>{digitalOceanPreflightAction.result.catalogSource}</strong>
              </div>
              <div>
                <span>Checked region</span>
                <strong>{digitalOceanPreflightAction.result.checkedRegion}</strong>
              </div>
              <div>
                <span>Checked size</span>
                <strong>{digitalOceanPreflightAction.result.checkedSize}</strong>
              </div>
              <div>
                <span>Mutation</span>
                <strong>{String(digitalOceanPreflightAction.result.mutation)}</strong>
              </div>
              <div>
                <span>Sketch node access</span>
                <strong>{digitalOceanPreflightAction.result.opsecBoundary.directSketchAccessFromAppHost ? "Direct" : "None from app host"}</strong>
              </div>
              <div>
                <span>Errors</span>
                <strong>{digitalOceanPreflightAction.result.errors.length ? digitalOceanPreflightAction.result.errors.join("; ") : "None"}</strong>
              </div>
            </div>
          ) : (
            <OperationsEmptyState message="Run the readiness check after saving and marking a DigitalOcean credential as default." />
          )}
          <div className="table-panel embedded" aria-label="DigitalOcean provider-smoke validation">
            <div className="section-heading">
              <div>
                <h4>Provider-smoke create/destroy</h4>
                <p>Create, inspect, destroy, and verify cleanup for one disposable DigitalOcean droplet.</p>
              </div>
              <StatusPill value={digitalOceanProviderSmokeAction.job?.status ?? digitalOceanProviderSmokeAction.status} />
            </div>
            <p className="guardrail-hint">This is a live provider mutation guarded by confirmation. It uses the DigitalOcean control-plane API only and does not SSH to sketch middle or edge nodes.</p>
            {digitalOceanProviderSmokeAction.message ? (
              <div className="inline-warning" role="status">
                {digitalOceanProviderSmokeAction.message}
              </div>
            ) : null}
            <div className="detail-grid test-deploy-grid">
              <label>
                <span>Type validate-digitalocean-sketch</span>
                <input
                  aria-label="DigitalOcean provider-smoke confirmation"
                  onChange={(event) =>
                    setDigitalOceanProviderSmokeAction((current) => ({
                      ...current,
                      confirmation: event.target.value
                    }))
                  }
                  placeholder="validate-digitalocean-sketch"
                  value={digitalOceanProviderSmokeAction.confirmation}
                />
              </label>
              <button
                className="danger-action compact"
                disabled={
                  providerRegionPolicyStatus !== "ready" ||
                  digitalOceanProviderSmokeAction.status === "running" ||
                  digitalOceanProviderSmokeAction.confirmation !== "validate-digitalocean-sketch"
                }
                onClick={onRunDigitalOceanProviderSmokeValidation}
                type="button"
              >
                Run Provider-Smoke Validation
              </button>
            </div>
            {digitalOceanProviderSmokeAction.job ? (
              <div className="detail-grid test-deploy-grid" aria-label="DigitalOcean provider-smoke job result">
                <div>
                  <span>Job</span>
                  <strong>{digitalOceanProviderSmokeAction.job.id}</strong>
                </div>
                <div>
                  <span>Status</span>
                  <strong>{digitalOceanProviderSmokeAction.job.status}</strong>
                </div>
                <div>
                  <span>Evidence</span>
                  <strong>{outboundJobEvidenceSummary(digitalOceanProviderSmokeAction.job)}</strong>
                </div>
              </div>
            ) : null}
          </div>
        </section>
          </>
        ) : null}
        {activeGlobalSettingsTab === "barragan-app" && isAdministrator ? (
        <section className="guided-review" aria-label="Barragan application settings">
          <div className="section-heading">
            <h3>Application settings</h3>
            <span>local development</span>
          </div>
          <div className="detail-grid">
            <div>
              <span>Default region</span>
              <strong>us-sanjose-1</strong>
            </div>
            <div>
              <span>Deployment compartment</span>
              <strong>barragan-testing</strong>
            </div>
            <div>
              <span>Mutation guardrail</span>
              <strong>explicit confirmation required</strong>
            </div>
            <div>
              <span>Runtime</span>
              <strong>FastAPI + OpenResty/React</strong>
            </div>
            <div>
              <span>Mode</span>
              <strong>pilot</strong>
            </div>
          </div>
        </section>
        ) : null}
      </section>
    );
  }

  const activeDashboardRows = dashboard?.engagementOverview?.active ?? [];
  const recentDashboardRows = [
    ...(dashboard?.engagementOverview?.recentlyEnded ?? []).map((row) => ({
      ...row,
      change: "Torn down",
      changedAt: row.endedAt
    })),
    ...(dashboard?.engagementOverview?.recentlyArchived ?? []).map((row) => ({
      ...row,
      change: "Archived",
      changedAt: row.archivedAt
    }))
  ];
  const dashboardWindowDays = dashboard?.engagementOverview?.windowDays ?? 30;
  const health = dashboard?.systemHealth;

  const dashboardReady = dashboardStatus === "ready" && dashboardResponseIsComplete(dashboard);

  return (
    <section
      aria-label="Global infrastructure dashboard"
      className="dashboard-grid"
      {...(dashboardReady ? {
        "data-barragan-dashboard-ready": "true",
        "data-dashboard-generated-at": dashboard!.generatedAt
      } : {})}
    >
      {stats.map((stat) => (
        <article className="metric" key={stat.label}>
          <span>{stat.label}</span>
          <strong>{stat.value}</strong>
        </article>
      ))}
      <article className="wide-panel">
        <div className="section-heading">
          <div>
            <h3>Engagement Activity</h3>
            <p>High-level view of active engagements and engagements torn down or archived in the last {dashboardWindowDays} days.</p>
            <p>Lifecycle and health reflect recorded deployment evidence. Refresh Provider Inventory checks current resources separately; these labels are not a live billing check.</p>
          </div>
          <div className="section-actions compact-actions">
            <button
              className="secondary-action compact"
              disabled={dashboardProviderRefreshStatus === "running"}
              onClick={onRefreshDashboardProviderInventory}
              type="button"
            >
              {dashboardProviderRefreshStatus === "running" ? "Refreshing" : "Refresh Provider Inventory"}
            </button>
            <StatusPill value={dashboard?.reconciliation?.status ?? "loading"} />
          </div>
        </div>
        {dashboardProviderRefreshStatus === "error" ? (
          <div className="inline-warning" role="status">
            Provider inventory refresh failed. Dashboard is showing local Barragan records.
          </div>
        ) : null}
        <div className="table-panel embedded operations-table" aria-label="Active engagement summary">
          <TableHeader columns={["Engagement", "Recorded Lifecycle", "Active Age", "Recorded Health", "Providers", "Regions", "Last Observed"]} />
          {activeDashboardRows.length ? (
            activeDashboardRows.map((row) => (
              <div className="table-row" key={`dashboard-active-${row.engagementId}`}>
                <span>{row.engagementName}</span>
                <StatusPill value={row.lifecycleState} />
                <span>{row.activeDurationLabel}</span>
                <StatusPill value={row.healthStatus} />
                <span>{operationListValue(row.providers, "N/A")}</span>
                <span>{operationListValue(row.regions, "N/A")}</span>
                <span>{formatOperationsTimestamp(row.lastCheckedAt)}</span>
              </div>
            ))
          ) : (
            <OperationsEmptyState message="No active engagement infrastructure is recorded right now." />
          )}
        </div>
        <div className="table-panel embedded operations-table" aria-label="Recent engagement changes">
          <TableHeader columns={["Engagement", "Change", "When", "Health", "Detail"]} />
          {recentDashboardRows.length ? (
            recentDashboardRows.map((row) => (
              <div className="table-row" key={`dashboard-recent-${row.engagementId}-${row.change}`}>
                <span>{row.engagementName}</span>
                <span>{row.change}</span>
                <span>{formatOperationsTimestamp(row.changedAt)}</span>
                <StatusPill value={row.healthStatus} />
                <span>{row.healthDetail}</span>
              </div>
            ))
          ) : (
            <OperationsEmptyState message={`No engagement teardown or archive events were recorded in the last ${dashboardWindowDays} days.`} />
          )}
        </div>
      </article>
      <article className="wide-panel">
        <div className="section-heading">
          <div>
            <h3>Barragan Health</h3>
            <p>Read-only checks for the control plane and provider visibility.</p>
          </div>
          <StatusPill value={health?.api?.status ?? "loading"} />
        </div>
        <div className="detail-grid test-deploy-grid" aria-label="Barragan health">
          <div>
            <span>API</span>
            <strong>{health?.api?.detail ?? "Loading"}</strong>
          </div>
          <div>
            <span>Database</span>
            <strong>{health?.database?.detail ?? "Loading"}</strong>
          </div>
          <div>
            <span>Disk</span>
            <strong>{health?.disk?.detail ?? "Loading"}</strong>
          </div>
          <div>
            <span>Providers</span>
            <strong>{health?.providers?.detail ?? "Loading"}</strong>
          </div>
        </div>
      </article>
      <ProviderInventoryPanel dashboard={dashboard} />
      <article className="wide-panel">
        <div className="section-heading">
          <div>
            <h3>Provider Tracking</h3>
            <p>{dashboard?.reconciliation?.detail ?? "Loading Barragan infrastructure inventory."}</p>
          </div>
          <div className="section-actions">
            <StatusPill value={dashboard?.systemHealth?.providers?.status ?? dashboard?.reconciliation?.status ?? "loading"} />
            {providerOrphanRecoveryAction.job ? (
              <button className="secondary-action compact" onClick={() => onOpenLifecycleConsole("provider")} type="button">
                <ListChecks aria-hidden="true" size={14} />
                Log
              </button>
            ) : null}
          </div>
        </div>
        {providerOrphanRecoveryAction.message ? (
          <div className="inline-warning" role="status">
            {providerOrphanRecoveryAction.message}
            {providerOrphanRecoveryAction.job ? ` Job ${providerOrphanRecoveryAction.job.id}.` : ""}
          </div>
        ) : null}
        {dashboard?.orphanCandidates?.length ? (
          <div className="table-panel embedded operations-table" aria-label="Provider orphan candidates">
            <TableHeader columns={["Engagement", "Provider", "Resource", "State", "Region", "Reason", "Actions"]} />
            {dashboard.orphanCandidates.map((candidate) => {
              const allowedActions = new Set(candidate.actions ?? []);
              const confirmationActive =
                providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId &&
                Boolean(providerOrphanRecoveryAction.confirmationToken);
              const confirmationMatches =
                confirmationActive &&
                providerOrphanRecoveryAction.confirmationValue === providerOrphanRecoveryAction.confirmationToken;
              return (
                <div className="table-row" key={`dashboard-orphan-${candidate.candidateId}`}>
                  <span>{candidate.engagementName || candidate.engagementId || "Unmatched"}</span>
                  <span>{candidate.provider}</span>
                  <span>{candidate.name || candidate.resourceId}</span>
                  <StatusPill value={candidate.lifecycleState} />
                  <span>{candidate.region || "N/A"}</span>
                  <span>{candidate.reason}</span>
                  <span className="section-actions compact-actions">
                    {allowedActions.has("track") ? (
                      <button
                        className="secondary-action compact"
                        disabled={providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId}
                        onClick={() => onRecoverProviderOrphan(candidate, "track")}
                        type="button"
                      >
                        Track
                      </button>
                    ) : null}
                    {allowedActions.has("mark_destroyed") ? (
                      <button
                        className="secondary-action compact"
                        disabled={providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId}
                        onClick={() => onRecoverProviderOrphan(candidate, "mark_destroyed")}
                        type="button"
                      >
                        Record Destroyed Note
                      </button>
                    ) : null}
                    {allowedActions.has("tear_down") ? (
                      <button
                        className="danger-action compact"
                        disabled={providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId}
                        onClick={() => onRecoverProviderOrphan(candidate, "tear_down")}
                        type="button"
                      >
                        Teardown Plan
                      </button>
                    ) : null}
                    {confirmationActive ? (
                      <span className="provider-recovery-confirmation">
                        <label>
                          <span>Type {providerOrphanRecoveryAction.confirmationToken}</span>
                          <input
                            aria-label={`Live teardown confirmation for ${candidate.name || candidate.resourceId}`}
                            onChange={(event) =>
                              onSetProviderOrphanTeardownConfirmation(candidate.candidateId, event.target.value)
                            }
                            type="text"
                            value={providerOrphanRecoveryAction.confirmationValue}
                          />
                        </label>
                        <button
                          className="danger-action compact"
                          disabled={(providerOrphanRecoveryAction.status === "running" && providerOrphanRecoveryAction.activeCandidateId === candidate.candidateId) || !confirmationMatches}
                          onClick={() =>
                            onRecoverProviderOrphan(candidate, "tear_down", {
                              mutation: true,
                              confirmation: providerOrphanRecoveryAction.confirmationValue
                            })
                          }
                          type="button"
                        >
                          Confirm Teardown
                        </button>
                      </span>
                    ) : null}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <OperationsEmptyState message="No provider orphan candidates are currently visible." />
        )}
      </article>
    </section>
  );
}

function topologySummary(revision: DeploymentRevision): string {
  const topology = revision.resolvedTopology as {
    nodeGroups?: unknown[];
    sketchChains?: unknown[];
    ingressRoutes?: unknown[];
  };
  return `${topology.nodeGroups?.length ?? 0} groups, ${topology.sketchChains?.length ?? 0} chains, ${topology.ingressRoutes?.length ?? 0} routes`;
}

function validationGateSummary(revision: DeploymentRevision): string {
  const gates = revision.validationGates ?? [];
  const passed = gates.filter((gate) => gate.status === "passed").length;
  const failed = gates.filter((gate) => gate.status === "failed").length;
  return `${passed} passed, ${failed} failed`;
}

function teardownConfirmationPhrase(engagement: EngagementSummary | null): string {
  const slug = (engagement?.name ?? "engagement")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return `teardown-${slug || "engagement"}`;
}

function engagementTeardownScopeSummary(scope: EngagementTeardownPreview["orderedScope"][number]): string {
  if (scope.id === "provider-keyed") {
    return scope.items.map((item) => {
      const count = Array.isArray(item.resources) ? item.resources.length : Number(item.resourceCount || 0);
      return `${String(item.provider || "provider")}: ${count} owned resource${count === 1 ? "" : "s"}`;
    }).join("; ");
  }
  if (scope.id === "outbound") {
    const channelCount = scope.items.reduce((total, item) => total + (Array.isArray(item.channelIds) ? item.channelIds.length : 0), 0);
    return `${channelCount} outbound channel${channelCount === 1 ? "" : "s"} across ${scope.items.length} chain${scope.items.length === 1 ? "" : "s"}`;
  }
  if (scope.id === "sketch") {
    if (scope.items.length && scope.items.every((item) => typeof item.savedPlanReceiptSha256 === "string")) {
      return `${scope.items.map((item) => String(item.provider)).join(" then ")} saved plans; no Sketch Apply occurred`;
    }
    if (scope.items.length && scope.items.every((item) =>
      typeof item.provider === "string" && typeof item.kind === "string" && typeof item.resourceCount === "number")) {
      return scope.items.map((item) =>
        `${String(item.provider)}: ${String(item.kind).replaceAll("_", " ")} (${Number(item.resourceCount)} owned resources)`
      ).join("; ");
    }
    if (!scope.items.length) {
      return "No deployed sketch chains";
    }
    return scope.items.map((item) => {
      const middle = typeof item.middle === "object" && item.middle !== null ? item.middle as Record<string, unknown> : {};
      const edges = Array.isArray(item.edges) ? item.edges : [];
      return `${String(item.chainId || "chain")} · ${String(item.assignedProxy || "proxy")} -> ${String(middle.provider || "middle")} ${String(middle.region || "")} -> ${edges.length} edge${edges.length === 1 ? "" : "s"}`;
    }).join("; ");
  }
  if (scope.id === "core") {
    const core = scope.items[0] ?? {};
    const proxyCount = Number(core.proxyCount || 0);
    return `Homebase and ${proxyCount} prox${proxyCount === 1 ? "y" : "ies"}`;
  }
  if (scope.id === "inspector-verify") {
    const targetCount = Number(scope.items[0]?.targetCount || 0);
    return targetCount ? `${targetCount} previously known public target${targetCount === 1 ? "" : "s"}` : "Explicit zero-target verification";
  }
  if (scope.id === "inspector-cleanup" && Array.isArray(scope.items[0]?.ownedProviderRecordIds)) {
    const count = scope.items[0].ownedProviderRecordIds.length;
    return count ? `${count} owned Inspector resource${count === 1 ? "" : "s"}` : "No retained Inspector recorded";
  }
  return scope.items[0]?.tracked ? "Tracked retained Inspector cleanup" : "No retained Inspector recorded";
}

function isMixedZeroApplyTeardownPreview(preview: EngagementTeardownPreview | null): boolean {
  const sketch = preview?.orderedScope.find((scope) => scope.id === "sketch");
  return Boolean(sketch?.items.length && sketch.items.every((item) =>
    typeof item.savedPlanReceiptSha256 === "string" &&
    typeof item.provider === "string"));
}

function coreRecreateConfirmationPhrase(engagement: EngagementSummary | null): string {
  const slug = (engagement?.name ?? "engagement")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return `recreate-core-${slug || "engagement"}`;
}

function hasActiveCoreInfrastructure(operations: EngagementOperationsOverview | null, job: JobRunDetail | null): boolean {
  if (job && ["pending_operator_teardown", "cleanup_not_verified"].includes(pilotRunValue(job, "finalCleanupStatus"))) {
    return true;
  }
  return Boolean(
    operations?.coreInfrastructure.some((host) => {
      const lifecycle = (host.lifecycleState || host.status || "").toLowerCase();
      if (host.lastKnown) {
        return false;
      }
      return lifecycle === "active" || lifecycle === "running" || lifecycle === "deployed" || lifecycle === "cleanup_not_verified";
    })
  );
}

function retainedSketchChainFieldsPresent(
  chain: Pick<SketchChainRecord, "status" | "deployJobId" | "nodes">
): boolean {
  return chain.status === "failed" && canonicalNonemptyString(chain.deployJobId) && chain.nodes.length > 0;
}

export function sketchBootstrapReconciliationRequired(
  job: Pick<JobRunDetail, "events"> | null
): boolean {
  return job?.events.some((event) => event.data.bootstrap === "reconciliation_required" ||
    event.data.reconciliationRequired === true || event.data.localQuiescenceUnproved === true) ?? false;
}

export function retainedSketchBootstrapEligible(
  chain: Pick<SketchChainRecord, "status" | "deployJobId" | "nodes">,
  job: Pick<JobRunDetail, "id" | "status" | "events"> | null
): boolean {
  return retainedSketchChainFieldsPresent(chain) &&
    job?.id === chain.deployJobId &&
    job.status === "failed" &&
    !sketchBootstrapReconciliationRequired(job) &&
    job.events.some((event) => event.data.bootstrap === "failed");
}

function runningCoreDeploymentEvidence(operations: EngagementOperationsOverview | null): { id: string; action: string; status: string } | null {
  const running = (operations?.lifecycle?.evidence ?? []).filter((row) =>
    row.kind === "core_job" && ["queued", "running"].includes(row.status) && typeof row.id === "string" && Boolean(row.id)
  );
  if (running.length !== 1) return null;
  return { id: running[0].id, action: "pilot_standard_rti_guarded_execute", status: running[0].status };
}

export function mixedSketchPublicationPending(
  plan: CoreInfrastructurePlan | null,
  operations: EngagementOperationsOverview | null,
  engagement?: { id: string; sketchStateSchema?: string } | null
): boolean {
  if (engagement?.sketchStateSchema === "provider-keyed-v2") {
    // Operations binds this summary to the exact current core on the server.
    // Missing or stale selection data cannot release the publication gate.
    if (!operations || operations.engagementId !== engagement.id) return true;
    if (["not_deployed", "tearing_down", "cleanup_required", "destroyed"].includes(operations.lifecycle?.state ?? "")) return false;
    if (operations.mixedInitialJob) return true;
    if (operations.lifecycle?.state !== "active") return true;
    const core = operations.coreJob;
    if (!core?.id || core.action !== "pilot_standard_rti_guarded_execute" || core.status !== "succeeded") return true;
    const publicationJobId = `job-provider-keyed-mixed-initial-${core.id.replace(/^job-/, "")}`;
    // The canonical publisher stamps its parent identity on every chain. Old
    // deployment rows must not release readiness for a different current core.
    const published = operations.sketchInfrastructure.filter((row) => row.status === "deployed" &&
      (row as typeof row & { deploymentJobId?: string }).deploymentJobId === publicationJobId);
    return !["digitalocean", "linode"].every((provider) => {
      const middles = published.filter((row) => row.provider === provider && row.role === "middle");
      return middles.some((middle) => published.some((row) => row.chainId === middle.chainId &&
        row.provider === provider && row.role === "edge"));
    });
  }
  return plan?.reviewedConfiguration?.sketchAuthorization?.kind === "bounded-mixed-post-core-v1" &&
    plan.status === "applied" &&
    ["deploying", "active"].includes(operations?.lifecycle?.state ?? "") &&
    operations?.sketchInfrastructure.length === 0;
}

export function infrastructureWorkflowMode(input: {
  operationsReady: boolean;
  operationsFailed?: boolean;
  lifecycleState: string;
  teardownJobPresent: boolean;
  teardownSelectionBlocked?: boolean;
  teardownJobComplete?: boolean;
  teardownRecoveryJobAvailable: boolean;
  teardownJobLoading?: boolean;
  teardownRequestPending?: boolean;
  teardownRequestUnconfirmed?: boolean;
  retainedBootstrapRecoveryAvailable: boolean;
  legacyChainCleanupAvailable?: boolean;
  activeCoreInfrastructure: boolean;
  currentCoreDeploymentLoaded?: boolean;
}): "teardown_recovery" | "deploying" | "running" | "blocked" | "loading" | "unavailable" | "fresh" | "historical" {
  if (input.teardownRequestUnconfirmed) return "blocked";
  if (input.teardownRequestPending) return "teardown_recovery";
  if (!input.operationsReady) {
    return input.operationsFailed ? "unavailable" : "loading";
  }
  if (input.teardownSelectionBlocked) return "blocked";
  // Operations reconciles deployment generations and verified cleanup. Retained
  // deployment outputs must never resurrect resources after canonical teardown.
  if (input.lifecycleState === "destroyed") {
    return "historical";
  }
  if (input.teardownJobLoading) return "loading";
  if (input.teardownRecoveryJobAvailable) {
    return "teardown_recovery";
  }
  const cleanupLifecycle = ["cleanup_required", "tearing_down"].includes(input.lifecycleState);
  if (
    (cleanupLifecycle && input.teardownJobPresent) ||
    input.lifecycleState === "tearing_down"
  ) {
    return "blocked";
  }
  if (input.retainedBootstrapRecoveryAvailable) {
    return "running";
  }
  if (input.legacyChainCleanupAvailable && input.activeCoreInfrastructure && !input.teardownJobPresent) {
    return "running";
  }
  if (input.lifecycleState === "cleanup_required") {
    return "blocked";
  }
  if (input.lifecycleState === "deploying") {
    if (input.teardownJobPresent && !input.teardownJobComplete) return "blocked";
    if (input.activeCoreInfrastructure) return "running";
    return input.currentCoreDeploymentLoaded ? "deploying" : "loading";
  }
  if (input.activeCoreInfrastructure) {
    return "running";
  }
  return input.lifecycleState === "not_deployed" ? "fresh" : "blocked";
}

export function buildDeploymentSteps(
  readiness: DisposableDeploymentReadiness,
  runStatus: "idle" | "running" | "ready" | "error",
  result: DisposableDeploymentResult | null,
  job: JobRunDetail | null = null,
  teardownInProgress = false,
  sketch: {
    sketchChain: SketchChainWithId | null;
    sketchChains?: SketchChainWithId[];
    sketchJob: JobRunDetail | null;
    sketchRunStatus: "idle" | "running" | "ready" | "error";
    outboundChannels?: EngagementOperationsOverview["outboundChannels"];
  } = { sketchChain: null, sketchJob: null, sketchRunStatus: "idle" }
): Array<DeploymentStep & { statusLabel: string }> {
  const awaitingInspection =
    job ? pilotRunValue(job, "finalCleanupStatus") === "pending_operator_teardown" : false;
  const destroyStatus = eventStepStatus(job, "Terraform destroy completed") ??
    (teardownInProgress ? "wip" : commandStepStatus(result, "destroy", runStatus));
  const cleanupStatus = eventStepStatus(job, "cleanup verification completed") ??
    statusFromResult(result?.cleanupVerification?.ok, teardownInProgress ? "pending" : "pending");
  const steps: DeploymentStep[] = [
    {
      id: "readiness",
      label: "Load readiness boundary",
      detail: `${readiness.target.name} in ${readiness.target.region}`,
      status: "done"
    },
    {
      id: "preflight",
      label: "Run OCI read preflight",
      detail: "List VCNs and boot volumes with instance principal before compute mutation.",
      status: eventStepStatus(job, "OCI read preflight completed") ??
        statusFromResult(result?.preflight?.ok, runStatus === "running" ? "wip" : "pending")
    },
    {
      id: "terraform-init",
      label: "Initialize Terraform workspace",
      detail: "Resolve the OCI provider in the disposable workspace.",
      status: eventStepStatus(job, "Terraform init completed") ?? commandStepStatus(result, "init", runStatus)
    },
    {
      id: "terraform-apply",
      label: readiness.topology ? "Create pilot Standard RTI nodes" : "Create disposable compute",
      detail: `Apply only ${
        readiness.expectedInstanceDisplayNames?.join(", ") ??
        readiness.expectedInstanceDisplayName ??
        readiness.expectedVcnDisplayName ??
        "the disposable validation target"
      } and its isolated network in ${readiness.target.name}.`,
      status: eventStepStatus(job, "Terraform apply completed") ?? commandStepStatus(result, "apply", runStatus)
    },
    {
      id: "ssh-readiness",
      label: "Wait for bounded SSH readiness",
      detail: `Use ${readiness.sshReadiness?.module ?? "ansible.builtin.wait_for_connection"} with workspace-local known hosts.`,
      status: eventStepStatus(job, "SSH readiness validation completed") ?? commandStepStatus(result, "wait_for_connection", runStatus)
    },
    {
      id: "ansible-ping",
      label: "Run Ansible ping",
      detail: "Validate SSH transport with ansible.builtin.ping only.",
      status: eventStepStatus(job, "Ansible ping validation completed") ?? commandStepStatus(result, "ping", runStatus)
    },
    {
      id: "ansible-facts",
      label: readiness.topology ? "Configure RTI base layout" : "Gather harmless facts",
      detail: readiness.topology
        ? "Create and verify the pilot /dropbox path plus homebase/proxy runtime directories."
        : "Run the validation playbook with facts/setup and no host configuration.",
      status: eventStepStatus(job, "Ansible bootstrap validation completed") ?? commandStepStatus(
        result,
        readiness.topology ? "ansible/bootstrap_validate.yml" : "ansible/validate.yml",
        runStatus
      )
    },
    {
      id: "ansible-capabilities",
      label: "Apply selected RTI capabilities",
      detail: "Configure the selected engagement capabilities on the core hosts.",
      status: eventStepStatus(job, "Ansible selected capabilities apply completed") ??
        activeCommandStepStatus(job, "ansible_capabilities")
    },
    {
      id: "inspection",
      label: "Ready for engagement operations",
      detail: "Core hosts stay running. Add team users, apply capabilities, then configure channels, DNS, and certificates as needed.",
      status: eventStepStatus(job, "operator inspection ready") ??
        (awaitingInspection ? "done" : runStatus === "ready" ? "pending" : "pending")
    }
  ];

  const activeSketchChains = sketch.sketchChains?.length
    ? sketch.sketchChains
    : sketch.sketchChain
      ? [sketch.sketchChain]
      : [];

  // A post-core sketch job has its own persisted lifecycle and console. Once
  // the core job is terminal, its console must remain terminal too instead of
  // borrowing an active sketch step and presenting core deployment as running.
  const showPostCoreSketchSteps = !job || ["queued", "running"].includes(job.status);
  if (activeSketchChains.length && showPostCoreSketchSteps) {
    const sketchApplyStatus =
      eventStepStatus(sketch.sketchJob, "terraform apply completed") ??
      eventStepStatus(sketch.sketchJob, "Linode sketch Terraform apply completed") ??
      (sketch.sketchRunStatus === "running"
        ? "wip"
        : sketch.sketchRunStatus === "ready"
          ? "done"
          : sketch.sketchRunStatus === "error"
            ? "failed"
            : awaitingInspection
              ? "wip"
              : "pending");
    steps.push(
      {
        id: "sketch-provision",
        label: "Provision sketch middle and edge nodes",
        detail: `${sketchChainSummary(activeSketchChains)} use provider APIs and Terraform; Barragan does not SSH directly to sketch nodes.`,
        status: sketchApplyStatus,
        active: sketchApplyStatus === "wip"
      },
      {
        id: "sketch-configure",
        label: "Configure outbound channels on proxies",
        detail: "Apply and validate the standard SOCKS egress listeners for each deployed sketch chain.",
        status: outboundChannelConfigurationStepStatus(sketch.outboundChannels ?? [], sketchApplyStatus),
        active: outboundChannelConfigurationStepStatus(sketch.outboundChannels ?? [], sketchApplyStatus) === "wip"
      }
    );
  }

  if (!awaitingInspection || teardownInProgress) {
    steps.push(
      {
        id: "terraform-destroy",
        label: readiness.topology ? "Tear down pilot Standard RTI nodes" : "Tear down disposable compute",
        detail: "Destroy the compute targets and isolated network when teardown is requested.",
        status: destroyStatus,
        active: teardownInProgress && destroyStatus !== "done"
      },
      {
        id: "cleanup",
        label: "Verify cleanup",
        detail: "Confirm no disposable validation compute instance remains in barragan-testing.",
        status: cleanupStatus,
        active: teardownInProgress && destroyStatus === "done" && cleanupStatus !== "done"
      }
    );
  }

  const stepsWithActiveDeployStep = markActiveDeploymentStep(steps, runStatus, teardownInProgress);
  if (runStatus === "error") {
    return stepsWithActiveDeployStep.map((step) => ({
      ...step,
      status: step.id === "readiness" ? step.status : step.status === "done" ? "done" : "failed",
      active: false,
      statusLabel: statusLabel(step.id === "readiness" ? step.status : step.status === "done" ? "done" : "failed")
    }));
  }

  return stepsWithActiveDeployStep.map((step) => ({ ...step, statusLabel: statusLabel(step.status) }));
}

export function outboundChannelConfigurationStepStatus(
  channels: EngagementOperationsOverview["outboundChannels"],
  sketchApplyStatus: DeploymentStepStatus
): DeploymentStepStatus {
  if (!channels.length) {
    return sketchApplyStatus === "done" ? "pending" : "pending";
  }
  const statuses = channels.map((channel) => operationValue(channel.validation?.status ?? channel.status, "").toLowerCase());
  if (statuses.some((status) => ["apply failed", "validation failed", "failed"].includes(status))) {
    return "failed";
  }
  if (statuses.every((status) => status === "validated" || status === "validated with warnings")) {
    return "done";
  }
  if (sketchApplyStatus === "done" || statuses.some((status) => status.includes("pending") || status.includes("config"))) {
    return "wip";
  }
  return "pending";
}

export function buildTeardownSteps(
  job: JobRunDetail | null,
  teardownStatus: "idle" | "confirming" | "running"
): Array<DeploymentStep & { statusLabel: string }> {
  if (job?.action === "provider_keyed_mixed_published_cleanup") {
    const labels = [
      "Review both saved provider destroy plans",
      "Destroy owned infrastructure and prove exact absence",
      "Reconcile engagement lifecycle"
    ];
    // The reservation acknowledgement is raw JobRunDetail. Only its explicit
    // initial phase is useful before projected child progress arrives.
    const phase = job.phase ?? (job.input.phase === "awaiting_both_destroy_plans" ? "destroy_plans" : undefined);
    const completed = phase === "complete" ? 3 :
      phase === "lifecycle_reconciliation" ? 2 :
      phase === "destroy_plans" ? 0 : 1;
    return labels.map((label, index) => {
      const status: DeploymentStepStatus = index < completed ? "done" :
        index === completed && ["queued", "running"].includes(job.status) ? "wip" : "pending";
      return { id: `published-mixed-cleanup-${index + 1}`, label,
        detail: "Barragan advances from its saved teardown evidence.", status,
        active: index === completed && ["queued", "running"].includes(job.status),
        statusLabel: statusLabel(status) };
    });
  }
  if (job?.action === "provider_keyed_mixed_zero_apply_cleanup" ||
      job?.action === "provider_keyed_mixed_interrupted_cleanup") {
    const interrupted = job.action === "provider_keyed_mixed_interrupted_cleanup";
    const source = job.input?.source as { ordered_providers?: string[]; scopes?: Array<{ provider?: string; selector_retirement_pending?: boolean }> } | undefined;
    const order = source?.ordered_providers ?? [];
    const selectorPending = source?.scopes?.some((scope) => scope.provider === "digitalocean" && scope.selector_retirement_pending === true);
    const labels = interrupted ? [
      "Save both reviewed provider destroy plans",
      ...order.map((provider) => `Verify ${provider} resources are absent`),
      "Review the exact core destroy plan",
      "Apply the saved core destroy plan",
      "Prove exact core resource absence",
      "Verify former public SSH targets from Inspector",
      ...(selectorPending ? ["Retire the owned provider selector"] : []),
      "Retire owned Inspector resources"
    ] : [
      "Review the exact core destroy plan",
      "Apply the saved core destroy plan",
      "Prove exact core resource absence",
      "Verify former public SSH targets from Inspector",
      "Retire owned Inspector resources"
    ];
    const completed = Number.isInteger(job.progress?.completed)
      ? Math.max(0, Math.min(labels.length, job.progress!.completed)) : 0;
    const steps: DeploymentStep[] = labels.map((label, index) => ({
      id: `mixed-cleanup-${index + 1}`,
      label,
      detail: "Barragan advances this phase from its saved evidence.",
      status: index < completed ? "done" :
        index === completed && job.phase === "attention" ? "failed" :
        index === completed && ["queued", "running"].includes(job.status) ? "wip" : "pending"
    }));
    return steps.map((step, index) => ({...step,
      active: index === completed && job.phase !== "attention" && completed < labels.length,
      statusLabel: statusLabel(step.status)}));
  }
  const attemptJob = job ? { ...job, events: currentJobAttemptEvents(job) } : null;
  const inspectorPreflightStarted = hasJobEvent(attemptJob, "Inspector teardown preflight started");
  const inspectorPreflightCompleted = hasJobEvent(attemptJob, "Inspector teardown preflight completed");
  const sketchStarted = hasJobEvent(attemptJob, "engagement sketch cleanup started");
  const coreStarted = hasJobEvent(attemptJob, "core and Inspector cleanup started");
  const inspectorVerificationFinished = hasJobEvent(attemptJob, "Inspector teardown verification completed") ||
    hasJobEvent(attemptJob, "Inspector teardown verification failed");
  const teardownFailed = hasJobEvent(attemptJob, "engagement teardown requires cleanup");
  const steps: DeploymentStep[] = [
    {
      id: "teardown-requested",
      label: "Teardown scope accepted",
      detail: "Barragan persisted the reviewed engagement cleanup snapshot.",
      status: eventStepStatus(attemptJob, "engagement teardown queued") ??
        eventStepStatus(attemptJob, "engagement teardown retry queued") ?? "pending"
    },
    {
      id: "inspector-preflight",
      label: "Establish Inspector vantage point",
      detail: "Before cleanup starts, Barragan verifies or prepares the external Inspector required for teardown checks.",
      status: inspectorPreflightCompleted || sketchStarted
        ? "done"
        : teardownFailed && inspectorPreflightStarted
          ? "failed"
          : inspectorPreflightStarted
            ? "wip"
            : "pending"
    },
    {
      id: "sketch-cleanup",
      label: "Remove outbound configuration and sketch chains",
      detail: "Outbound configuration is removed before every snapshotted middle and edge is destroyed.",
      status: coreStarted ? "done" : teardownFailed && sketchStarted ? "failed" : sketchStarted ? "wip" : "pending"
    },
    {
      id: "core-cleanup",
      label: "Destroy core infrastructure",
      detail: "Core cleanup starts only after every reviewed sketch chain is verified clean.",
      status: inspectorVerificationFinished ? "done" : teardownFailed && coreStarted ? "failed" : coreStarted ? "wip" : "pending"
    },
    {
      id: "inspector-teardown-verification",
      label: "Verify retired public endpoints",
      detail: "The retained Inspector checks that retired public listeners and DNS names no longer behave like active engagement infrastructure.",
      status: eventStepStatus(attemptJob, "Inspector teardown verification completed") ??
        eventStepStatus(attemptJob, "Inspector teardown verification failed") ??
        "pending"
    },
    {
      id: "inspector-cleanup",
      label: "Tear down Inspector",
      detail: "Barragan destroys retained Inspector hosts after external teardown validation has completed.",
      status: eventStepStatus(attemptJob, "Inspector cleanup completed") ??
        eventStepStatus(attemptJob, "Inspector cleanup failed") ??
        "pending"
    },
    {
      id: "teardown-finished",
      label: "Reconcile engagement lifecycle",
      detail: "Barragan reports success only after the complete owned resource graph is verified clean.",
      status: eventStepStatus(attemptJob, "engagement lifecycle reconciled") ??
        eventStepStatus(attemptJob, "engagement teardown requires cleanup") ?? "pending"
    }
  ];

  return markActiveDeploymentStep(steps, teardownStatus === "running" ? "running" : "ready", false)
    .map((step) => ({ ...step, statusLabel: statusLabel(step.status) }));
}

function hasJobEvent(job: JobRunDetail | null, message: string): boolean {
  return Boolean(job?.events.some((event) => event.message === message));
}

function markActiveDeploymentStep(
  steps: DeploymentStep[],
  runStatus: "idle" | "running" | "ready" | "error",
  teardownInProgress: boolean
): DeploymentStep[] {
  if (teardownInProgress || runStatus !== "running" || steps.some((step) => step.active)) {
    return steps;
  }
  const firstIncomplete = steps.find((step) => step.status !== "done");
  if (!firstIncomplete) {
    return steps;
  }
  return steps.map((step) => ({
    ...step,
    active: step.id === firstIncomplete.id,
    status: step.id === firstIncomplete.id && step.status === "pending" ? "wip" : step.status
  }));
}

function visibleDeploymentConsoleSteps(
  steps: Array<DeploymentStep & { statusLabel: string }>
): Array<DeploymentStep & { statusLabel: string }> {
  return steps.filter((step) => step.status !== "pending" || Boolean(step.active));
}

function statusFromResult(value: boolean | undefined, fallback: DeploymentStepStatus): DeploymentStepStatus {
  if (value === true) {
    return "done";
  }
  if (value === false) {
    return "failed";
  }
  return fallback;
}

function cidrsFromText(value: string): string[] {
  const seen = new Set<string>();
  return value
    .split(/[,\n]/)
    .map((cidr) => cidr.trim())
    .filter((cidr) => {
      if (!cidr || seen.has(cidr)) {
        return false;
      }
      seen.add(cidr);
      return true;
    });
}

export function publishedTeardownTiming(
  job: JobRunDetail,
  nowMilliseconds: number,
  operations?: Pick<EngagementOperationsOverview, "engagementId" | "teardownSelection" | "teardownJob"> | null
): { elapsedSeconds: number | null; lastActivitySeconds: number | null } {
  const timestamp = (value: unknown): number | null => {
    if (typeof value !== "string" || !value.trim()) return null;
    const at = Date.parse(value);
    return Number.isFinite(at) && at <= nowMilliseconds ? at : null;
  };
  // Terminal pilot GETs retain the raw journal and may omit dispatch metadata.
  // Operations can supply the clock only for this exact verified terminal parent.
  const projected = operations?.teardownJob;
  const terminalProjection = job.action === "provider_keyed_mixed_published_cleanup" && job.status === "succeeded" &&
    operations?.engagementId === jobEngagementId(job) && operations?.teardownSelection?.state === "exact" &&
    projected?.id === job.id && projected.action === job.action && projected.status === job.status &&
    projected.recoveryState === "complete" && projected.dispatch?.status === "succeeded" ? projected : null;
  const dispatch = terminalProjection?.dispatch ?? job.dispatch;
  const started = timestamp(dispatch?.startedAt);
  const terminal = job.status === "succeeded" || dispatch?.status === "succeeded";
  const end = terminal ? timestamp(dispatch?.finishedAt) : nowMilliseconds;
  const heartbeat = timestamp(dispatch?.heartbeatAt);
  return {
    elapsedSeconds: started === null || end === null || end < started ? null : Math.floor((end - started) / 1000),
    lastActivitySeconds: heartbeat === null ? null : Math.floor((nowMilliseconds - heartbeat) / 1000)
  };
}

const infrastructureStallThresholdSeconds = 90;

export function currentInfrastructureCommandActivity(
  job: JobRunDetail | null,
  nowMilliseconds: number
): InfrastructureCommandActivity | null {
  if (!job || !["queued", "running"].includes(job.status)) {
    return null;
  }
  const progressEvents = job.events.filter((event) =>
    ["command_started", "command_heartbeat", "ansible_task", "command_completed"].includes(stringValue(event.data.eventKind))
  );
  const latest = progressEvents.at(-1);
  if (!latest || stringValue(latest.data.eventKind) === "command_completed") {
    return null;
  }
  const step = stringValue(latest.data.step);
  const related = progressEvents.filter((event) => stringValue(event.data.step) === step);
  const started = related.find((event) => stringValue(event.data.eventKind) === "command_started") ?? latest;
  const latestTask = [...related].reverse().find((event) => stringValue(event.data.eventKind) === "ansible_task");
  const latestPlay = [...related].reverse().find((event) => stringValue(event.data.play));
  const startedAt = Date.parse(stringValue(started.data.startedAt) || stringValue(started.data.observedAt));
  const observedAt = Date.parse(stringValue(latest.data.observedAt));
  const elapsedSeconds = Number.isFinite(startedAt) ? Math.max(0, Math.floor((nowMilliseconds - startedAt) / 1000)) : 0;
  const lastActivitySeconds = Number.isFinite(observedAt)
    ? Math.max(0, Math.floor((nowMilliseconds - observedAt) / 1000))
    : elapsedSeconds;
  return {
    state: lastActivitySeconds > infrastructureStallThresholdSeconds ? "possibly_stalled" : "working",
    phase: stringValue(latest.data.phase) || "Infrastructure command",
    elapsedSeconds,
    lastActivitySeconds,
    play: latestPlay ? stringValue(latestPlay.data.play) : "",
    task: latestTask ? stringValue(latestTask.data.task) : ""
  };
}

function activeCommandStepStatus(job: JobRunDetail | null, step: string): DeploymentStepStatus {
  if (!job) {
    return "pending";
  }
  const related = job.events.filter((event) => stringValue(event.data.step) === step);
  const latest = related.at(-1);
  if (!latest) {
    return "pending";
  }
  if (stringValue(latest.data.eventKind) === "command_completed") {
    return latest.level === "error" ? "failed" : "done";
  }
  return ["command_started", "command_heartbeat", "ansible_task"].includes(stringValue(latest.data.eventKind))
    ? "wip"
    : "pending";
}

export function infrastructureCommandActivitySummary(activity: InfrastructureCommandActivity): string {
  const state = activity.state === "possibly_stalled" ? "Possibly stalled" : "Working";
  const task = activity.task ? ` Current task: ${activity.task}.` : activity.play ? ` Current play: ${activity.play}.` : "";
  return `${state} — ${activity.phase}. ${formatActivityDuration(activity.elapsedSeconds)} elapsed; last activity ${formatActivityDuration(activity.lastActivitySeconds)} ago.${task}`;
}

export function infrastructureConsoleCurrentTask(
  activity: InfrastructureCommandActivity | null,
  activeStepLabel?: string | null
): string {
  return activity?.task || activity?.play || activeStepLabel || "Waiting for job activity";
}

function formatActivityDuration(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder ? `${minutes}m ${remainder}s` : `${minutes}m`;
}

function eventStepStatus(job: JobRunDetail | null, message: string): DeploymentStepStatus | null {
  const event = [...(job?.events ?? [])].reverse().find((entry) => entry.message === message);
  if (!event) {
    return null;
  }
  if (event.level === "error") {
    return "failed";
  }
  if (event.level === "warning" && event.data.status === "not_recorded") {
    return "pending";
  }
  return "done";
}

function hasTeardownActivity(job: JobRunDetail | null): boolean {
  if (!job) {
    return false;
  }
  if (["provider_keyed_mixed_zero_apply_cleanup", "provider_keyed_mixed_interrupted_cleanup", "provider_keyed_mixed_published_cleanup"].includes(job.action)) {
    return true;
  }
  return job.events.some((event) =>
    [
      "operator teardown requested",
      "Terraform destroy completed",
      "cleanup verification completed",
      "Inspector teardown verification completed",
      "Inspector teardown verification failed",
      "Inspector cleanup completed",
      "Inspector cleanup failed",
      "pilot Standard RTI teardown finished"
      ,"engagement teardown queued"
      ,"engagement sketch cleanup started"
      ,"sketch chain cleanup verified"
      ,"core and Inspector cleanup started"
      ,"engagement resource cleanup gates passed"
      ,"engagement lifecycle reconciled"
      ,"engagement teardown requires cleanup"
    ].includes(event.message)
  );
}

export function mixedZeroApplyProgressMessage(job: JobRunDetail): string {
  const labels: Record<string, string> = {
    destroy_plans: "Saving both provider destroy plans",
    linode_absence: "Verifying Linode resources are absent",
    digitalocean_absence: "Verifying DigitalOcean resources are absent",
    core_destroy_preview: "Reviewing the exact core destroy plan",
    core_destroy_apply: "Destroying core infrastructure",
    core_absence: "Verifying exact core resource absence",
    public_negative: "Checking retired public targets from Inspector",
    selector_retirement: "Retiring the owned provider selector",
    inspector_retirement: "Retiring the owned Inspector",
    lifecycle_reconciliation: "Reconciling engagement lifecycle",
    complete: "Engagement infrastructure teardown complete",
    attention: "Cleanup needs attention at its saved phase"
  };
  const phaseKey = job.phase ?? (job.action === "provider_keyed_mixed_published_cleanup" &&
    job.input.phase === "awaiting_both_destroy_plans" ? "destroy_plans" : undefined);
  const phase = labels[phaseKey ?? ""] ?? "Preparing mixed infrastructure cleanup";
  const completed = job.progress?.completed;
  const total = job.progress?.total;
  return Number.isInteger(completed) && Number.isInteger(total) && total! > 0
    ? `${phase} · ${completed}/${total} phases complete`
    : phase;
}

function jobEngagementId(job: JobRunDetail | null): string | null {
  const engagementId = job?.input?.engagementId;
  return typeof engagementId === "string" && engagementId.trim() ? engagementId : null;
}

function isEngagementTeardownAction(action: string | undefined): boolean {
  return action === "engagement_comprehensive_teardown" ||
    action === "provider_keyed_mixed_zero_apply_cleanup" ||
    action === "provider_keyed_mixed_interrupted_cleanup" ||
    action === "provider_keyed_mixed_published_cleanup";
}

type TeardownSelectionContext = Pick<EngagementOperationsOverview,
  "engagementId" | "coreJob" | "teardownSelection" | "teardownJob">;

function hasSealedInitialCleanup(job: JobRunDetail | null): boolean {
  const input = job?.input;
  const scope = input?.scopeSnapshot;
  return Boolean(input && typeof input === "object" && ("publishedInitialCleanupAuthority" in input ||
    (scope && typeof scope === "object" && "publishedInitialCleanupSeal" in scope) ||
    (Array.isArray(job?.events) && job.events.some((event) => event.data && typeof event.data === "object" &&
      "publishedInitialCleanupAuthority" in event.data))));
}

// Operations has already validated the supported cleanup source and targets.
// This binds the display to that exact selected parent; it grants no authority
// to mutate infrastructure and does not reproduce backend cryptography.
export function selectedSealedCleanupState(
  job: JobRunDetail | null,
  operations?: TeardownSelectionContext | null
): "active" | "recoverable" | "complete" | null {
  if (!job || !hasSealedInitialCleanup(job) || job.action !== "engagement_comprehensive_teardown") return null;
  const engagementId = jobEngagementId(job);
  const parent = operations?.teardownJob;
  if (!engagementId || job.targetType !== "engagement" || job.targetId !== engagementId ||
      operations?.engagementId !== engagementId || operations.teardownSelection?.state !== "exact" ||
      !parent || parent.id !== job.id || parent.action !== job.action || parent.status !== job.status ||
      !canonicalNonemptyString(job.input.coreJobId) || operations.coreJob?.id !== job.input.coreJobId) return null;
  const scope = job.input.scopeSnapshot;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return null;
  const seal = scope.publishedInitialCleanupSeal;
  const marker = job.input.publishedInitialCleanupAuthority;
  const queued = job.events[0]?.data;
  const queuedMarker = queued?.publishedInitialCleanupAuthority;
  const schema = "published-initial-failed-http-cleanup-v1";
  if (!seal || typeof seal !== "object" || Array.isArray(seal) || seal.schema !== schema ||
      typeof seal.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(seal.sha256) ||
      scope.engagementId !== engagementId || scope.coreJobId !== job.input.coreJobId ||
      seal.engagementId !== engagementId || seal.coreJobId !== job.input.coreJobId ||
      !canonicalNonemptyString(scope.snapshotId) || queued?.snapshotId !== scope.snapshotId ||
      !marker || typeof marker !== "object" || Array.isArray(marker) ||
      Object.keys(marker).sort().join(",") !== "schema,sha256" ||
      marker.schema !== schema || marker.sha256 !== seal.sha256 ||
      !queuedMarker || typeof queuedMarker !== "object" || Array.isArray(queuedMarker) ||
      Object.keys(queuedMarker).sort().join(",") !== "schema,sha256" ||
      queuedMarker.schema !== marker.schema || queuedMarker.sha256 !== marker.sha256) return null;
  if (["queued", "running"].includes(job.status) && parent.recoveryState === "in_progress") return "active";
  if (job.status === "failed" && parent.recoveryState === "recoverable") return "recoverable";
  if (job.status === "succeeded" && parent.recoveryState === "complete") return "complete";
  return null;
}

function isRecoverableEngagementTeardownJob(job: JobRunDetail | null, operations?: TeardownSelectionContext | null): boolean {
  if (hasSealedInitialCleanup(job)) {
    return ["active", "recoverable"].includes(selectedSealedCleanupState(job, operations) ?? "");
  }
  if (job?.action === "provider_keyed_mixed_published_cleanup") {
    const engagementId = jobEngagementId(job);
    const input = job.input;
    const coreJobId = input?.coreJobId;
    const rawSource = input?.publishedSource;
    const source = rawSource && typeof rawSource === "object" && !Array.isArray(rawSource) ? rawSource as Record<string, unknown> : null;
    const six = input?.sourceKind === "published-six-node-v1" || input?.sourceKind === "unpublished-six-node-cleanup-v1";
    const nested = source?.six_node_source;
    const identity = six && source && Object.keys(source).sort().join(",") === "parent_job_id,provider_states,six_node_source" &&
      nested && typeof nested === "object" && !Array.isArray(nested) ? nested as Record<string, unknown> :
      !six && input?.sourceKind === undefined && source && !("six_node_source" in source) ? source : null;
    const order = identity?.[six ? "provider_order" : "ordered_providers"];
    return Boolean(engagementId && job.targetType === "engagement" && job.targetId === engagementId &&
      identity && identity.engagement_id === engagementId && identity.core_job_id === coreJobId &&
      source?.parent_job_id === input?.publishedParentId && canonicalNonemptyString(input?.publishedParentId) &&
      Array.isArray(order) && order.length === 2 && order.every((provider) => typeof provider === "string" && ["linode", "digitalocean"].includes(provider)) && new Set(order).size === 2 &&
      Array.isArray(source?.provider_states) && source.provider_states.length === 2 && source.provider_states.every((row, index) =>
        row && typeof row === "object" && !Array.isArray(row) && row.provider === order[index]) &&
      Array.isArray(input?.orderedProviders) && input.orderedProviders.length === 2 && input.orderedProviders.every((provider, index) => provider === order[index]) &&
      canonicalNonemptyString(input?.corePlanId) && identity.core_plan_id === input.corePlanId &&
      ["queued", "running"].includes(job.status) &&
      input?.schema === "mixed-published-initial-cleanup-v1" &&
      (input.sourceKind === undefined || ["published-six-node-v1", "unpublished-six-node-cleanup-v1"].includes(String(input.sourceKind))) &&
      canonicalNonemptyString(coreJobId) &&
      job.id === `job-provider-keyed-mixed-published-cleanup-${coreJobId.replace(/^job-/, "")}`);
  }
  if (job?.action === "provider_keyed_mixed_zero_apply_cleanup" ||
      job?.action === "provider_keyed_mixed_interrupted_cleanup") {
    const engagementId = jobEngagementId(job);
    const source = job.input?.source;
    const coreJobId = job.input?.coreJobId;
    return Boolean(engagementId && job.targetType === "engagement" &&
      job.targetId === engagementId && ["queued", "running", "failed"].includes(job.status) &&
      typeof coreJobId === "string" && coreJobId.trim() &&
      typeof job.input?.sourceSha256 === "string" && /^[0-9a-f]{64}$/.test(job.input.sourceSha256) &&
      source && typeof source === "object" && !Array.isArray(source));
  }
  return isRecoverableComprehensiveTeardownJob(job);
}

function isRecoverableComprehensiveTeardownJob(job: JobRunDetail | null): boolean {
  if (!job || job.action !== "engagement_comprehensive_teardown" || !["failed", "queued", "running"].includes(job.status)) return false;
  const engagementId = jobEngagementId(job);
  const coreJobId = job.input?.coreJobId;
  const scope = job.input?.scopeSnapshot;
  if (!engagementId || job.targetType !== "engagement" || job.targetId !== engagementId || typeof coreJobId !== "string" || !coreJobId.trim()) return false;
  if (!scope || typeof scope !== "object" || Array.isArray(scope)) return false;
  const boundary = scope as Record<string, unknown>;
  const core = boundary.core;
  const inspector = boundary.inspector;
  const chains = boundary.chains;
  const targets = boundary.publicVerificationTargets;
  return boundary.engagementId === engagementId && boundary.coreJobId === coreJobId &&
    typeof boundary.snapshotId === "string" && Boolean(boundary.snapshotId.trim()) &&
    typeof boundary.confirmationPhrase === "string" && Boolean(boundary.confirmationPhrase.trim()) &&
    validUniqueStrings(boundary.ownedProviderRecordIds) && validUniqueStrings(boundary.excludedUnmanagedProviderRecords) &&
    Array.isArray(chains) && validRecoveryChains(chains) && Array.isArray(targets) && validRecoveryTargets(targets) &&
    Boolean(core && typeof core === "object" && !Array.isArray(core) &&
      (core as Record<string, unknown>).jobId === coreJobId && typeof (core as Record<string, unknown>).workspace === "string" &&
      Number.isInteger((core as Record<string, unknown>).proxyCount) && Number((core as Record<string, unknown>).proxyCount) >= 0) &&
    Boolean(inspector && typeof inspector === "object" && !Array.isArray(inspector) &&
      typeof (inspector as Record<string, unknown>).tracked === "boolean" &&
      validUniqueStrings((inspector as Record<string, unknown>).ownedProviderRecordIds) &&
      validStringMap((inspector as Record<string, unknown>).recordOwners) &&
      Number.isInteger((inspector as Record<string, unknown>).verificationTargetCount) &&
      (inspector as Record<string, unknown>).verificationTargetCount === targets.length);
}

function validUniqueStrings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(canonicalNonemptyString) && new Set(value).size === value.length;
}

function validStringMap(value: unknown): boolean {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) &&
    Object.entries(value as Record<string, unknown>).every(([key, item]) => canonicalNonemptyString(key) && canonicalNonemptyString(item)));
}

function canonicalNonemptyString(value: unknown): value is string {
  return typeof value === "string" && Boolean(value) && value === value.trim();
}

function validRecoveryChains(value: unknown[]): boolean {
  const ids: string[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return false;
    const chain = item as Record<string, unknown>;
    if (!canonicalNonemptyString(chain.chainId) || !canonicalNonemptyString(chain.assignedProxy) ||
        typeof chain.status !== "string" || typeof chain.deployJobId !== "string" ||
        (chain.deployJobId !== "" && !canonicalNonemptyString(chain.deployJobId)) || typeof chain.alreadyClean !== "boolean" ||
        !validUniqueStrings(chain.outboundChannelIds)) return false;
    if (!chain.middle || typeof chain.middle !== "object" || Array.isArray(chain.middle) ||
        !["provider", "region"].every((key) => canonicalNonemptyString((chain.middle as Record<string, unknown>)[key]))) return false;
    if (!Array.isArray(chain.edges) || !chain.edges.length || !chain.edges.every((edge) => edge && typeof edge === "object" && !Array.isArray(edge) &&
      ["id", "provider", "region"].every((key) => canonicalNonemptyString((edge as Record<string, unknown>)[key])))) return false;
    const edgeIds = chain.edges.map((edge) => (edge as Record<string, unknown>).id as string);
    if (new Set(edgeIds).size !== edgeIds.length) return false;
    ids.push(chain.chainId);
  }
  return new Set(ids).size === ids.length;
}

function validRecoveryTargets(value: unknown[]): boolean {
  const identities = new Set<string>();
  const ids = new Set<string>();
  for (const item of value) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return false;
    const target = item as Record<string, unknown>;
    if (typeof target.id !== "string" || !target.id || target.id !== target.id.trim() || ids.has(target.id) ||
        typeof target.host !== "string" || !target.host || canonicalRecoveryHost(target.host) !== target.host) return false;
    ids.add(target.id);
    const optionalKeys = Object.keys(target).filter((key) => !["id", "type", "host", "port"].includes(key));
    if (!optionalKeys.every((key) => ["expectedIp", "targetGroup", "service", "purpose"].includes(key) &&
      typeof target[key] === "string" && Boolean(target[key]) && target[key] === (target[key] as string).trim())) return false;
    if ("targetGroup" in target && !["core-public-management", "sketch-public-management"].includes(String(target.targetGroup))) return false;
    let identity = "";
    if (target.type === "tcp-forbidden") {
      if (!Number.isInteger(target.port) || Number(target.port) < 1 || Number(target.port) > 65535) return false;
      identity = `${target.type}:${target.host}:${target.port}`;
    } else if (target.type === "dns-absent") {
      if ("port" in target || !Object.keys(target).every((key) => ["id", "type", "host", "expectedIp", "service", "purpose"].includes(key))) return false;
      if ("expectedIp" in target && (typeof target.expectedIp !== "string" || !target.expectedIp)) return false;
      identity = `${target.type}:${target.host}`;
    } else return false;
    if (identities.has(identity)) return false;
    identities.add(identity);
  }
  return true;
}

function canonicalRecoveryHost(value: string): string {
  const candidate = value.trim();
  if (!candidate || candidate !== value || candidate !== candidate.toLowerCase() || candidate.endsWith(".")) return "";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate)) {
    return candidate.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255 && String(Number(part)) === part) ? candidate : "";
  }
  if (candidate.includes(":")) return /^[0-9a-f:]+$/.test(candidate) ? candidate : "";
  return candidate.includes(".") && candidate.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ? candidate : "";
}

function commandStepStatus(
  result: DisposableDeploymentResult | null,
  commandName: string,
  runStatus: "idle" | "running" | "ready" | "error"
): DeploymentStepStatus {
  const command = result?.commandsRun?.find((entry) =>
    entry.command.some((part) => part.includes(commandName))
  );
  if (command) {
    return command.ok ? "done" : "failed";
  }
  return runStatus === "ready" ? "failed" : "pending";
}

function statusLabel(status: DeploymentStepStatus): string {
  if (status === "done") {
    return "DONE";
  }
  if (status === "wip") {
    return "WIP";
  }
  if (status === "failed") {
    return "FAILED";
  }
  return "PENDING";
}

function statusFromPilotJob(job: JobRunDetail): "running" | "ready" | "error" {
  if (job.status === "failed" || job.status === "cancelled") {
    return "error";
  }
  if (job.status === "queued" || job.status === "running") {
    return "running";
  }
  return "ready";
}

function inboundChannelReady(channel: InboundChannelFormState): boolean {
  return Boolean(
    channel.domain.trim() &&
      channel.protocol.trim() &&
      channel.externalPort.trim() &&
      channel.terminatesOn.trim() &&
      channel.service.trim() &&
      channel.internalPort.trim()
  );
}

function inboundChannelToInput(channel: EngagementOperationsOverview["inboundChannels"][number]): InboundChannelInput {
  return {
    channelId: channel.channelId,
    ...(channel.chainId ? { chainId: channel.chainId } : {}),
    ...(channel.edgeComponentId ? { edgeComponentId: channel.edgeComponentId } : {}),
    ...(channel.middleComponentId ? { middleComponentId: channel.middleComponentId } : {}),
    domain: channel.domain,
    protocol: channel.protocol,
    mode: channel.mode ?? "tcp-forward",
    externalPort: channel.externalPort,
    ...(channel.relayPort ? { relayPort: channel.relayPort } : {}),
    ...(channel.middleRelayPort ? { middleRelayPort: channel.middleRelayPort } : {}),
    ...(channel.proxyRelayPort ? { proxyRelayPort: channel.proxyRelayPort } : {}),
    edge: channel.edge,
    middle: channel.middle,
    proxy: channel.proxy,
    terminatesOn: channel.terminatesOn,
    service: channel.service,
    internalPort: channel.internalPort,
    purpose: channel.purpose,
    status: channel.status,
    ...(channel.validationProfile ? { validationProfile: channel.validationProfile } : {}),
    ...(channel.validation ? { validation: channel.validation } : {}),
    ...(channel.artifactTargets ? { artifactTargets: channel.artifactTargets } : {}),
    ...(channel.ingressAssessment ? { ingressAssessment: channel.ingressAssessment } : {})
  };
}

function inboundChannelToForm(channel: EngagementOperationsOverview["inboundChannels"][number]): InboundChannelFormState {
  return {
    channelId: channel.channelId,
    chainId: channel.chainId ?? "",
    edgeComponentId: channel.edgeComponentId ?? "",
    middleComponentId: channel.middleComponentId ?? "",
    domain: channel.domain,
    protocol: channel.protocol || "HTTPS",
    mode: channel.mode ?? "tcp-forward",
    externalPort: channel.externalPort,
    relayPort: channel.relayPort ?? channel.proxyRelayPort ?? "",
    middleRelayPort: channel.middleRelayPort ?? channel.relayPort ?? "",
    proxyRelayPort: channel.proxyRelayPort ?? channel.relayPort ?? "",
    edge: channel.edge,
    middle: channel.middle,
    proxy: channel.proxy,
    terminatesOn: channel.terminatesOn,
    service: channel.service,
    internalPort: channel.internalPort,
    purpose: channel.purpose,
    status: channel.status || "Not Ready",
    validationProfile: normalizedInboundValidationProfile(channel.validationProfile)
  };
}

function normalizedInboundValidationProfile(profile: InboundValidationProfile | undefined): InboundValidationProfile {
  const type = isInboundValidationProfileType(profile?.type) ? profile.type : defaultInboundValidationProfile.type;
  const option = inboundValidationProfileOptions.find((candidate) => candidate.type === type);
  return {
    ...profile,
    type,
    label: profile?.label || option?.label || type
  };
}

function isInboundValidationProfileType(value: unknown): value is InboundValidationProfileType {
  return typeof value === "string" && inboundValidationProfileOptions.some((candidate) => candidate.type === value);
}

function inboundValidationProfileLabel(
  profile: InboundValidationProfile | undefined,
  validation: EngagementOperationsOverview["inboundChannels"][number]["validation"] | undefined
): string {
  if (validation?.profileLabel) {
    return validation.profileLabel;
  }
  return normalizedInboundValidationProfile(profile).label ?? defaultInboundValidationProfile.label ?? "Temporary TCP listener";
}

function inboundExpectedValidationResult(channel: EngagementOperationsOverview["inboundChannels"][number]): string {
  const validation = channel.validation;
  if (validation?.expectedResponse) {
    return validation.expectedResponse;
  }
  if (channel.validationProfile?.expectedResponse) {
    return channel.validationProfile.expectedResponse;
  }
  if (validation?.expectedMarker) {
    return validation.expectedMarker;
  }
  return "Not Rendered";
}

function inboundRouteValidationStatus(channel: EngagementOperationsOverview["inboundChannels"][number]): string {
  const status = operationValue(channel.validation?.status ?? channel.status, "Not Ready");
  if (status === "Validated") {
    return "Route Validated";
  }
  if (status === "Validation Failed") {
    return "Route Validation Failed";
  }
  if (status === "Pending Validation") {
    return "Route Pending Validation";
  }
  if (status === "Pending Apply") {
    return "Route Not Run";
  }
  if (status === "Apply Blocked") {
    return "Route Apply Blocked";
  }
  if (status === "Not Run") {
    return "Route Not Run";
  }
  if (status === "Not Ready") {
    return "Route Not Ready";
  }
  return status;
}

function inboundChannelAwaitingValidationRefresh(channel: EngagementOperationsOverview["inboundChannels"][number]): boolean {
  const routeStatus = inboundRouteValidationStatus(channel).toLowerCase();
  return routeStatus.includes("pending validation") || routeStatus.includes("not run");
}

function inboundPublicIngressStatus(channel: EngagementOperationsOverview["inboundChannels"][number]): string {
  if (channel.validation?.externalIngressVerified === true) {
    return "Public Ingress Verified";
  }
  if (channel.validation?.externalIngressVerified === false) {
    return "Public Ingress Not Verified";
  }
  return "Public Ingress Not Checked";
}

function outboundChannelToInput(channel: EngagementOperationsOverview["outboundChannels"][number]): OutboundChannelInput {
  return {
    ...(channel.channelId ? { channelId: channel.channelId } : {}),
    chainId: channel.chainId,
    ...(channel.edgeIndex ? { edgeIndex: channel.edgeIndex } : {}),
    ...(channel.edgeCount ? { edgeCount: channel.edgeCount } : {}),
    proxy: channel.proxy,
    middle: channel.middle,
    edge: channel.edge,
    port: channel.port,
    region: channel.region,
    provider: channel.provider,
    domain: channel.domain,
    purpose: channel.purpose,
    status: channel.status,
    ...(channel.profileName ? { profileName: channel.profileName } : {}),
    ...(channel.publicationPath ? { publicationPath: channel.publicationPath } : {}),
    ...(channel.validation ? { validation: channel.validation } : {}),
    ...(channel.artifactTargets ? { artifactTargets: channel.artifactTargets } : {})
  };
}

function outboundChannelActionId(channel: EngagementOperationsOverview["outboundChannels"][number]): string {
  return channel.channelId || channel.chainId;
}

function upsertInboundChannel(channels: InboundChannelInput[], draft: InboundChannelFormState): InboundChannelInput[] {
  const candidate: InboundChannelInput = { ...draft, status: draft.status || "Not Ready" };
  if (!candidate.relayPort?.trim()) {
    delete candidate.relayPort;
  }
  if (!candidate.middleRelayPort?.trim()) {
    delete candidate.middleRelayPort;
  }
  if (!candidate.proxyRelayPort?.trim()) {
    delete candidate.proxyRelayPort;
  }
  const channelId = candidate.channelId?.trim();
  if (!channelId) {
    return [...channels, candidate];
  }
  const index = channels.findIndex((channel) => channel.channelId === channelId);
  if (index < 0) {
    return [...channels, candidate];
  }
  return channels.map((channel, currentIndex) =>
    currentIndex === index
      ? {
          ...channel,
          ...candidate,
          validation: undefined,
          artifactTargets: undefined,
          ingressAssessment: undefined,
          status: candidate.status || "Not Ready"
        }
      : channel
  );
}

function upsertOutboundChannel(channels: OutboundChannelInput[], draft: OutboundChannelFormState): OutboundChannelInput[] {
  const candidate: OutboundChannelInput = { ...draft, status: draft.status || "Not Ready" };
  const chainId = candidate.chainId?.trim();
  const channelId = candidate.channelId?.trim() || chainId;
  if (!chainId) {
    return [...channels, candidate];
  }
  const index = channels.findIndex((channel) => (channel.channelId || channel.chainId) === channelId);
  if (index < 0) {
    return [...channels, candidate];
  }
  return channels.map((channel, currentIndex) =>
    currentIndex === index
      ? {
          ...channel,
          ...candidate,
          validation: undefined,
          artifactTargets: undefined,
          status: candidate.status || "Not Ready"
        }
      : channel
  );
}

function outboundChannelReady(channel: OutboundChannelFormState): boolean {
  return Boolean(channel.proxy.trim() && channel.port.trim() && channel.domain.trim());
}

function pilotRunValue(job: JobRunDetail, key: string): string {
  const finalEvent = [...job.events].reverse().find((event) => event.data[key] !== undefined);
  const inputValue = job.input[key];
  const value = finalEvent?.data[key] ?? inputValue;
  return value === undefined || value === null || value === "" ? "not reported" : String(value);
}

function connectionDetailsFromJob(job: JobRunDetail | null): ConnectionDetail[] {
  if (!job || pilotRunValue(job, "finalCleanupStatus") !== "pending_operator_teardown") {
    return [];
  }
  const event = [...(job?.events ?? [])]
    .reverse()
    .find((entry) => Array.isArray(entry.data.connectionDetails));
  const details = event?.data.connectionDetails;
  if (!Array.isArray(details)) {
    return [];
  }
  return details
    .map((entry) => connectionDetailFromUnknown(entry))
    .filter((entry): entry is ConnectionDetail => entry !== null);
}

function connectionDetailFromUnknown(value: unknown): ConnectionDetail | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const displayName = stringValue(record.displayName);
  const sshAlias = stringValue(record.sshAlias) || displayName;
  const publicIp = stringValue(record.publicIp);
  const privateIp = stringValue(record.privateIp);
  const sshUser = stringValue(record.sshUser) || "ubuntu";
  if (!displayName || !publicIp) {
    return null;
  }
  return {
    role: stringValue(record.role) || displayName,
    displayName,
    sshAlias,
    publicIp,
    privateIp,
    sshUser,
    sshCommand: stringValue(record.sshCommand) || `ssh ${sshAlias}`,
    services: Array.isArray(record.services)
      ? record.services.map((service) => String(service)).filter(Boolean)
      : ["SSH"],
  };
}

function buildSshConfigStanza(hosts: ConnectionDetail[]): string {
  const homebase = hosts.find((host) => host.role === "homebase") ?? hosts[0];
  if (!homebase) {
    return "";
  }
  return hosts
    .map((host) => {
      const hostname = host.role === "homebase" ? host.publicIp : host.privateIp || host.publicIp;
      const proxyJump = host.role === "homebase" ? [] : [`    ProxyJump ${homebase.sshAlias}`];
      return [
        `Host ${host.sshAlias}`,
        `    HostName ${hostname}`,
        ...proxyJump
      ].join("\n");
    })
    .join("\n\n");
}

function normalizeOperatorSshConfig(stanza: string): string {
  const sanitized = stanza
    .split(/\r?\n/)
    .filter((line) => !/^\s*(User|IdentityFile|IdentitiesOnly)\b/i.test(line))
    .join("\n")
    .replace(/#\s*LocalForward\s+59(?:\d{2}|xx)\s+127\.0\.0\.1:59(?:\d{2}|xx)/g, "# LocalForward 5901 127.0.0.1:59xx")
    .trim();
  if (!sanitized) {
    return "";
  }
  return ensureVncForwardingGuidance(sanitized);
}

function ensureVncForwardingGuidance(stanza: string): string {
  const hasUidGuidance = stanza.includes("Your port number is (5900 + (UID - 6000) + 1)");
  const hasPlaceholderForward = stanza.includes("# LocalForward 5901 127.0.0.1:59xx");
  if (hasUidGuidance && hasPlaceholderForward) {
    return stanza;
  }
  const guidance = [
    "    ## Keep 5901 as your local listener unless it conflicts; change 59xx to your remote VNC port.",
    "    ## Your port number is (5900 + (UID - 6000) + 1)",
    "    # LocalForward 5901 127.0.0.1:59xx"
  ];
  const lines = stanza.split(/\r?\n/);
  const insertAfter = lines.findIndex((line, index) => index > 0 && /^\s*HostName\s+/i.test(line));
  if (insertAfter === -1) {
    return [...lines, ...guidance].join("\n");
  }
  return [
    ...lines.slice(0, insertAfter + 1),
    ...guidance,
    ...lines.slice(insertAfter + 1)
  ].join("\n");
}

export function buildSketchSshConfigStanza(
  operations: EngagementOperationsOverview | null,
  sketchSshKey: SketchSshKey | null
): string {
  if (!operations?.sketchInfrastructure?.length) {
    return "";
  }
  const activeNodes = operations.sketchInfrastructure.filter(
    (node) => node.status !== "removed" && node.status !== "destroyed" && Boolean(node.hostname) && Boolean(node.publicIp)
  );
  const middleByChain = new Map(
    activeNodes
      .filter((node) => node.role === "middle")
      .map((node) => [node.chainId, node])
  );
  const keyHint = sketchSshKey?.privateKeyName
    ? [`    IdentityFile ~/.ssh/${sketchSshKey.privateKeyName}`, "    IdentitiesOnly yes"]
    : ["    # IdentityFile ~/.ssh/<downloaded-sketch-private-key>", "    # IdentitiesOnly yes"];
  return activeNodes
    .filter((node) => node.role === "middle" || node.role === "edge")
    .map((node) => {
      const proxy = operatorSketchProxyAlias(operations, node.proxy);
      const middle = middleByChain.get(node.chainId);
      const proxyJump = node.role === "edge" && middle?.hostname
        ? `${proxy},${middle.hostname}`
        : proxy;
      return [
        `Host ${node.hostname}`,
        `    HostName ${node.publicIp}`,
        "    User user",
        ...keyHint,
        `    ProxyJump ${proxyJump}`
      ].join("\n");
    })
    .join("\n\n");
}

function operatorSketchProxyAlias(
  operations: EngagementOperationsOverview,
  recordedProxy: string
): string {
  const selectedProxy = shortHostName(recordedProxy || "proxy01");
  const homebaseLabel = operations.coreInfrastructure.find((host) => host.role === "homebase")?.hostname
    .trim().toLowerCase().split(".", 1)[0] ?? "";
  const engagementName = homebaseLabel.startsWith("homebase-") ? homebaseLabel.slice("homebase-".length) : "";
  return operations.coreInfrastructure.find(
    (host) => host.role === "proxy" && hostProxyMatches(host.hostname, selectedProxy, engagementName)
  )?.hostname ?? (recordedProxy || "proxy01");
}

function buildEngagementOverviewMarkdown(
  engagement: EngagementSummary | null,
  operations: EngagementOperationsOverview | null,
  sshConfigStanza: string
): string {
  if (!operations) {
    return "";
  }
  const sections = [
    `# Engagement Overview: ${engagement?.name ?? operations.engagementId}`,
    "## Status Summary",
    [
      `- Engagement: ${engagement?.name ?? operations.engagementId}`,
      `- Engagement status: ${engagement?.status ?? "unknown"}`,
      `- Health: ${operationValue(operations.healthSummary.status, "unknown")}`,
      `- Health detail: ${operationValue(operations.healthSummary.detail, "N/A")}`,
      `- Hosts: ${coreHostCountLabel(operations)}`,
      `- Sketch nodes: ${operations.sketchInfrastructure.length}`,
      `- Outbound channels: ${operations.outboundChannels.length}`,
      `- Inbound channels: ${operations.inboundChannels.length}`,
      `- Last probe: ${formatOperationsTimestamp(operations.healthSummary.lastCheckedAt)}`,
      `- Active job: ${operations.activeJob ? `${operations.activeJob.id} (${operations.activeJob.status})` : "none"}`
    ].join("\n"),
    "## Housekeeping Items",
    operations.housekeepingItems.trim() || "_No housekeeping items recorded._",
    "## Core Infrastructure",
    markdownTable(
      ["Hostname", "Role", "Status", "Public IP", "Private IP", "Region", "Compartment", "Services", "Health"],
      operations.coreInfrastructure.map((host) => [
        operationValue(host.hostname, "Not Deployed"),
        operationValue(host.role, "N/A"),
        operationValue(host.lifecycleState ?? host.status, "unknown"),
        operationValue(host.publicIp, "Not Deployed"),
        operationValue(host.privateIp, "Not Deployed"),
        operationValue(host.region, "N/A"),
        operationValue(host.compartment, "N/A"),
        operationListValue(host.services, "N/A"),
        operationHealthSummary(host.health)
      ]),
      "_No deployed core infrastructure has been recorded._"
    ),
    "## Sketch Infrastructure",
    markdownTable(
      ["Chain", "Role", "Status", "Hostname", "Public IP", "Provider", "Region", "Proxy"],
      operations.sketchInfrastructure.map((node) => [
        operationValue(node.chainId, "N/A"),
        operationValue(node.role, "N/A"),
        node.burned
          ? `${operationValue(node.status, "Not Ready")} (burned${node.burnedNote ? `: ${node.burnedNote}` : ""})`
          : operationValue(node.status, "Not Ready"),
        operationValue(node.hostname, "Not Deployed"),
        operationValue(node.publicIp, "Not Deployed"),
        operationValue(node.provider, "N/A"),
        operationValue(node.region, "N/A"),
        operationValue(node.proxy, "Not Deployed")
      ]),
      "_No sketch middle or edge nodes are configured._"
    ),
    "## Outbound Channels",
    markdownTable(
      ["Proxy", "Middle", "Edge", "Port", "Region", "Provider", "Domain", "Purpose", "Status"],
      operations.outboundChannels.map((channel) => [
        operationValue(channel.proxy, "Not Deployed"),
        operationValue(channel.middle, "Not Deployed"),
        operationValue(channel.edge, "Not Deployed"),
        operationValue(channel.port, "N/A"),
        operationValue(channel.region, "N/A"),
        operationValue(channel.provider, "N/A"),
        defangDomainField(channel.domain),
        operationValue(channel.purpose, "N/A"),
        operationValue(channel.status, "Not Ready")
      ]),
      "_No outbound sketch channels are configured._"
    ),
    "## Inbound Channels",
    markdownTable(
      ["Domain", "Protocol", "External Port", "Edge", "Middle", "Proxy", "Terminates On", "Service", "Internal Port", "Purpose", "Status"],
      operations.inboundChannels.map((channel) => [
        defangDomainField(channel.domain),
        operationValue(channel.protocol, "N/A"),
        operationValue(channel.externalPort, "N/A"),
        operationValue(channel.edge, "Not Deployed"),
        operationValue(channel.middle, "Not Deployed"),
        operationValue(channel.proxy, "Not Deployed"),
        operationValue(channel.terminatesOn, "Not Deployed"),
        operationValue(channel.service, "N/A"),
        operationValue(channel.internalPort, "N/A"),
        operationValue(channel.purpose, "N/A"),
        operationValue(channel.status, "Not Ready")
      ]),
      "_No inbound channels are configured._"
    ),
    "## SSH config",
    sshConfigStanza ? ["```sshconfig", sshConfigStanza, "```"].join("\n") : "_SSH config has not been recorded._"
  ];
  return `${sections.join("\n\n")}\n`;
}

function markdownDownloadName(engagement: EngagementSummary | null, operations: EngagementOperationsOverview | null): string {
  const seed = engagement?.name || operations?.engagementId || "engagement";
  const slug = seed.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "engagement";
  return `${slug}-overview.md`;
}

function markdownTable(headers: string[], rows: string[][], emptyText: string): string {
  if (!rows.length) {
    return emptyText;
  }
  return [
    `| ${headers.map(markdownTableCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(markdownTableCell).join(" | ")} |`)
  ].join("\n");
}

function markdownTableCell(value: string): string {
  const normalized = operationValue(value, "N/A");
  return normalized.replace(/\r?\n/g, "<br>").replace(/\|/g, "\\|");
}

function operationHealthSummary(health?: OperationsHealth | null): string {
  if (!health) {
    return "unknown";
  }
  const status = operationValue(health.status, "unknown");
  const stale = health.stale ? " stale" : "";
  const detail = operationValue(health.detail, "");
  return detail ? `${status}${stale}: ${detail}` : `${status}${stale}`;
}

function defangDomainField(value: string | null | undefined): string {
  const normalized = operationValue(value, "N/A");
  if (!isPlainDomainName(normalized)) {
    return normalized;
  }
  return normalized.replace(/\./g, " dot ");
}

function isPlainDomainName(value: string): boolean {
  const normalized = value.trim();
  if (
    !normalized.includes(".") ||
    normalized.includes("://") ||
    normalized.includes("/") ||
    normalized.includes(":") ||
    normalized.includes("@") ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(normalized)
  ) {
    return false;
  }
  return normalized.split(".").every((label) =>
    Boolean(label) &&
    /^[A-Za-z0-9-]+$/.test(label) &&
    !label.startsWith("-") &&
    !label.endsWith("-")
  );
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function jobRecordSummary(record: Record<string, unknown>): string {
  const entries = Object.entries(record);
  if (entries.length === 0) {
    return "none";
  }
  return entries
    .slice(0, 4)
    .map(([key, value]) => `${key}=${summaryValue(value)}`)
    .join("; ");
}

function eventDataSummary(data: Record<string, unknown>): string {
  const keys = ["status", "ok", "remainingCount", "mutationStatus", "ansibleStatus", "finalCleanupStatus", "workspaceDir"];
  return keys
    .filter((key) => data[key] !== undefined && data[key] !== null)
    .map((key) => `${key}=${summaryValue(data[key])}`)
    .join("; ");
}

function applyOutboundConfirmationToken(chainId: string): string {
  return `apply-outbound-${chainId}`;
}

function validateOutboundConfirmationToken(chainId: string): string {
  return `validate-outbound-${chainId}`;
}

function applyInboundConfirmationToken(channelId: string): string {
  return `apply-inbound-${channelId}`;
}

function validateInboundConfirmationToken(channelId: string): string {
  return `validate-inbound-${channelId}`;
}

function removeInboundConfirmationToken(channelId: string): string {
  return `remove-inbound-${channelId}`;
}

function sketchDeployConfirmationToken(chain: Pick<SketchChainRecord, "middleProvider" | "edgeProvider" | "edges">): string {
  if (chain.middleProvider !== chain.edgeProvider || chain.edges?.some((edge) => edge.provider !== chain.middleProvider)) {
    return "mutate-mixed-provider-sketch-testing";
  }
  return chain.middleProvider === "digitalocean"
    ? "mutate-digitalocean-sketch-testing"
    : "mutate-linode-sketch-testing";
}

function inboundChannelRequiresRemoveConfirmation(channel: EngagementOperationsOverview["inboundChannels"][number]): boolean {
  return inboundChannelHasLiveArtifacts(channel);
}

function inboundChannelHasLiveArtifacts(channel: EngagementOperationsOverview["inboundChannels"][number]): boolean {
  return ["Pending Validation", "Apply Failed", "Validated", "Validation Failed"].includes(channel.status);
}

function backflipsApplyConfirmationToken(): string {
  return "apply-service-backflips";
}

function desktopDesiredApps(action: DesktopServiceActionState): DesktopServiceDesiredApp[] {
  return action.catalog.map((app) => ({
    slug: app.slug,
    enabled: Boolean(action.desiredApps[app.slug])
  }));
}

function desktopDesiredAppsFromCatalog(
  apps: DesktopServiceApp[],
  placements: Array<Record<string, unknown>>,
  currentDesiredApps: Record<string, boolean>
): Record<string, boolean> {
  const hasDesktopPlacements = placements.some((candidate) => stringValue(candidate.serviceType) === "desktop-app");
  return Object.fromEntries(
    apps.map((app) => {
      const placement = placements.find((candidate) => stringValue(candidate.serviceId) === `desktop-${app.slug}` && stringValue(candidate.serviceType) === "desktop-app");
      if (placement) {
        return [app.slug, !["Removed", "Failed"].includes(stringValue(placement.status))];
      }
      if (!hasDesktopPlacements && Object.prototype.hasOwnProperty.call(currentDesiredApps, app.slug)) {
        return [app.slug, Boolean(currentDesiredApps[app.slug])];
      }
      return [app.slug, false];
    })
  );
}

function desktopServicePlacementsFromJob(job: JobRunDetail): Array<Record<string, unknown>> {
  for (const event of [...job.events].reverse()) {
    const placements = arrayValue(recordValue(event.data).servicePlacements).filter((placement): placement is Record<string, unknown> =>
      typeof placement === "object" && placement !== null && !Array.isArray(placement)
    );
    if (placements.length) {
      return placements;
    }
  }
  return [];
}

function booleanRecordEquals(left: Record<string, boolean>, right: Record<string, boolean>): boolean {
  const leftKeys = Object.keys(left);
  const rightKeys = Object.keys(right);
  if (leftKeys.length !== rightKeys.length) {
    return false;
  }
  return leftKeys.every((key) => left[key] === right[key]);
}

function webStaticSiteSlug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function webStaticSitePathSlug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[./\\]+/g, "_")
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^[-_]+|[-_]+$/g, "");
}

function webStaticServiceReady(form: WebStaticServiceFormState): boolean {
  const port = Number(form.internalPort);
  return Boolean(
    webStaticSitePathSlug(form.siteName) &&
      form.domain.trim() &&
      port === Number(defaultWebStaticInternalPort)
  );
}

function webStaticServiceRequest(form: WebStaticServiceFormState): WebStaticServiceRequest {
  return {
    proxyId: form.proxyId,
    siteName: form.siteName,
    domain: form.domain,
    internalPort: defaultWebStaticInternalPort,
    contentAction: form.contentAction ?? "preserve"
  };
}

function webStaticRequestIdentity(request: WebStaticServiceRequest): string {
  return JSON.stringify({ proxyId: request.proxyId, siteName: request.siteName,
    domain: request.domain, internalPort: request.internalPort });
}

function webStaticServiceRequestFromPlacement(
  placement: ServicePlacement,
  placements: NonNullable<EngagementOperationsOverview["servicePlacements"]>
): WebStaticServiceRequest | null {
  const siteName = placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId);
  const proxyId = placement.hostId || "";
  if (!siteName || !proxyId) {
    return null;
  }
  return {
    proxyId,
    siteName,
    domain: placement.domain || `${siteName}.invalid`,
    internalPort: defaultWebStaticInternalPort,
    indexHtml: defaultWebStaticIndexHtml
  };
}

function nextWebStaticSiteName(placements: NonNullable<EngagementOperationsOverview["servicePlacements"]>): string {
  const names = new Set(
    placements
      .map((placement) => placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId))
      .filter((name): name is string => Boolean(name))
  );
  if (!names.has("static-web")) {
    return "static-web";
  }
  let index = 2;
  while (names.has(`static-web-${index}`)) {
    index += 1;
  }
  return `static-web-${index}`;
}

function webStaticSiteNameFromServiceId(serviceId?: string): string {
  return serviceId?.startsWith("web-") ? serviceId.slice(4) : "";
}

function webStaticPlacementContentPath(placement: ServicePlacement): string {
  const siteName = placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId) || "static-web";
  return `/opt/web/${siteName}/html/`;
}

function webStaticPlacementPublicUrl(
  placement: ServicePlacement,
  operations: EngagementOperationsOverview | null,
  _engagementName: string
): string {
  if (!operations || placement.status !== "Configured") {
    return "";
  }
  const placementDomain = (placement.domain ?? "").trim().toLowerCase();
  const placementPort = String(placement.port ?? "").trim();
  const placementProxy = coreHostBySemanticId(operations, String(placement.hostId ?? ""));
  if (!placementProxy || placementProxy.role !== "proxy") return "";
  const channel = operations.inboundChannels.find((candidate) => {
    const candidateDomain = String(candidate.domain ?? "").trim().toLowerCase();
    const sameDomain = !placementDomain || candidateDomain === placementDomain;
    const samePort = placementPort && String(candidate.internalPort ?? "").trim() === placementPort;
    const sameService = Boolean(placement.serviceId && candidate.serviceId === placement.serviceId);
    const sameProxy = candidate.terminatesOn === placementProxy.hostname;
    const staticWebChannel = String(candidate.service ?? "").toLowerCase() === "static web";
    return sameDomain && (sameService || samePort) && sameProxy && staticWebChannel && candidate.status === "Validated";
  });
  if (!channel) {
    return "";
  }
  const exactEdge = channel.chainId && channel.edgeComponentId
    ? inboundSelectedEdge(operations, channel.chainId, channel.edgeComponentId, channel.edge)
    : null;
  const legacyEdges = operations.sketchInfrastructure.filter((node) =>
    node.hostname === channel.edge && node.role === "edge" && !node.burned &&
    operationValue(node.status, "").toLowerCase() === "deployed"
  );
  const edge = exactEdge ?? (legacyEdges.length === 1 ? legacyEdges[0] : null);
  if (!edge?.publicIp || edge.publicIp === "Not Deployed") {
    return "";
  }
  const https = channel.mode === "https-openresty" || String(channel.protocol).toUpperCase() === "HTTPS";
  const scheme = https ? "https" : "http";
  const defaultPort = https ? "443" : "80";
  const portSuffix = channel.externalPort === defaultPort ? "" : `:${channel.externalPort}`;
  const hostname = placementDomain || edge.publicIp;
  return `${scheme}://${hostname}${portSuffix}/`;
}

function inboundDraftFromWebStaticPlacement(
  placement: ServicePlacement,
  operations: EngagementOperationsOverview | null,
  engagementName: string
): InboundChannelFormState | null {
  if (!operations || placement.status !== "Configured") {
    return null;
  }
  const proxyId = placement.hostId || "";
  const coreProxy = coreHostBySemanticId(operations, proxyId);
  if (!coreProxy || coreProxy.role !== "proxy") return null;
  const edge = uniqueActiveEdgeForProxy(operations, proxyId);
  const attachment = edge ? inboundEdgeAttachment(operations, edge.chainId, edge.componentId ?? "", edge.hostname, engagementName) : null;
  const siteName = placement.siteName || webStaticSiteNameFromServiceId(placement.serviceId) || "Static Web";
  const domain = placement.domain || `${webStaticSiteSlug(siteName)}.invalid`;
  return {
    ...emptyInboundChannelForm,
    chainId: edge?.chainId ?? "",
    edgeComponentId: edge?.componentId ?? "",
    middleComponentId: attachment?.middleComponentId ?? "",
    edge: edge?.hostname ?? "",
    middle: attachment?.middleHostname ?? "",
    proxy: attachment?.proxyHostname ?? "",
    protocol: "HTTP",
    mode: "http-openresty",
    externalPort: "80",
    terminatesOn: attachment?.proxyHostname ?? coreProxy.hostname,
    service: "Static Web",
    serviceId: placement.serviceId ?? "",
    serviceType: placement.serviceType ?? "web-static",
    internalPort: "80",
    domain,
    purpose: `${siteName} web traffic`,
    validationProfile: {
      type: "http",
      label: "HTTP response"
    }
  };
}

function inboundDraftFromGenericPlacement(
  placement: ServicePlacement,
  operations: EngagementOperationsOverview | null,
  engagementName: string
): InboundChannelFormState | null {
  if (!operations || placement.status !== "Active") {
    return null;
  }
  const targetHost = placement.hostId || "";
  const coreTarget = coreHostBySemanticId(operations, targetHost);
  if (!coreTarget) return null;
  const wantsProxySpecificEdge = targetHost.startsWith("proxy");
  if (wantsProxySpecificEdge !== (coreTarget.role === "proxy")) return null;
  const edge = uniqueActiveEdgeForProxy(operations, wantsProxySpecificEdge ? targetHost : "");
  const attachment = edge ? inboundEdgeAttachment(operations, edge.chainId, edge.componentId ?? "", edge.hostname, engagementName) : null;
  const protocol = String(placement.protocol || "tcp").toLowerCase();
  const isUdp = protocol === "udp";
  return {
    ...emptyInboundChannelForm,
    chainId: edge?.chainId ?? "",
    edgeComponentId: edge?.componentId ?? "",
    middleComponentId: attachment?.middleComponentId ?? "",
    edge: edge?.hostname ?? "",
    middle: attachment?.middleHostname ?? "",
    proxy: attachment?.proxyHostname ?? "",
    protocol: isUdp ? "UDP" : "TCP",
    mode: isUdp ? "udp-forward" : "tcp-forward",
    terminatesOn: targetHost === "homebase" ? attachment?.homebaseHostname ?? coreTarget.hostname : attachment?.proxyHostname ?? coreTarget.hostname,
    service: placement.service || "Custom Listener",
    serviceId: placement.serviceId ?? "",
    serviceType: placement.serviceType ?? "generic",
    internalPort: placement.port || "18090",
    domain: "",
    purpose: placement.purpose || `${placement.service || "Custom Listener"} ingress`,
    validationProfile: placement.validationProfile ?? defaultValidationProfileForGenericProtocol(protocol)
  };
}

function uniqueActiveEdgeForProxy(
  operations: EngagementOperationsOverview,
  proxyId: string
): EngagementOperationsOverview["sketchInfrastructure"][number] | null {
  const matches = (operations.sketchInfrastructure ?? []).filter((host) =>
    host.role === "edge" &&
    Boolean(host.chainId.trim() && host.componentId?.trim()) &&
    !host.burned && operationValue(host.status, "").toLowerCase() === "deployed" &&
    host.proxy === host.assignedProxyId && Boolean(host.assignedProxyId?.match(/^proxy[0-9]+$/)) &&
    (!proxyId || host.assignedProxyId === proxyId)
  );
  return matches.length === 1 ? matches[0] : null;
}

function webStaticTerminationHost(
  operations: EngagementOperationsOverview | null,
  hostId: string
): string {
  return coreHostBySemanticId(operations, hostId)?.hostname ?? hostId;
}

function coreHostBySemanticId(
  operations: EngagementOperationsOverview | null,
  hostId: string
): EngagementOperationsOverview["coreInfrastructure"][number] | null {
  const semanticId = hostId.trim();
  if (!/^(?:homebase|proxy[0-9]+)$/.test(semanticId) || !operations) return null;
  const expectedRole = semanticId === "homebase" ? "homebase" : "proxy";
  const candidates = operations.coreInfrastructure.filter((host) => semanticId === "homebase"
    ? host.role === "homebase"
    : host.hostId === semanticId || host.logicalName === semanticId);
  const valid = candidates.filter((host) =>
    host.hostId === semanticId && host.logicalName === semanticId && host.role === expectedRole &&
    host.hostname === host.expectedHostname &&
    new RegExp(`^${semanticId}-[a-z0-9]+(?:-[a-z0-9]+)*$`).test(host.hostname)
  );
  return candidates.length === 1 && valid.length === 1 ? valid[0] : null;
}

function webStaticFormContentDirectory(form: WebStaticServiceFormState): string {
  const siteName = webStaticSitePathSlug(form.siteName) || "static-web";
  return `/opt/web/${siteName}/html/`;
}

function webStaticServiceContentDirectory(service: WebStaticServiceActionResult["service"]): string {
  const siteName = typeof service.config.siteName === "string" && service.config.siteName ? service.config.siteName : service.name;
  return `/opt/web/${siteName}/html/`;
}

function genericServiceReady(form: GenericServiceFormState): boolean {
  const port = Number(form.internalPort);
  return Boolean(
    form.name.trim() &&
      form.targetHost.trim() &&
      ["tcp", "udp", "http", "https"].includes(String(form.protocol).toLowerCase()) &&
      Number.isInteger(port) &&
      port >= 1 &&
      port <= 65535
  );
}

function genericServiceRequest(form: GenericServiceFormState): GenericServiceRequest {
  return {
    ...(form.serviceId ? { serviceId: form.serviceId } : {}),
    name: form.name.trim(),
    targetHost: form.targetHost,
    internalPort: form.internalPort,
    protocol: String(form.protocol).toLowerCase(),
    scriptPath: form.scriptPath?.trim() ?? "",
    purpose: form.purpose?.trim() ?? "",
    tags: Array.isArray(form.tags) ? form.tags : genericTagsFromText(String(form.tags ?? "")),
    notes: form.notes?.trim() ?? "",
    validationProfile: form.validationProfile ?? defaultValidationProfileForGenericProtocol(form.protocol)
  };
}

function defaultValidationProfileForGenericProtocol(protocol: string): InboundValidationProfile {
  const normalized = protocol.toLowerCase();
  if (normalized === "http") {
    return { type: "http", label: "HTTP check" };
  }
  if (normalized === "udp") {
    return { type: "manual", label: "Manual validation" };
  }
  return { type: "tcp-connect", label: "TCP reachability" };
}

function validationProfileLabel(value: string): string {
  const labels: Record<string, string> = {
    "temporary-listener": "Temporary TCP listener",
    "tcp-connect": "TCP reachability",
    "tcp-send-receive": "TCP send/expect",
    http: "HTTP check",
    "udp-send-receive": "UDP send/expect",
    manual: "Manual validation"
  };
  return labels[value] ?? value;
}

function genericTagsFromText(value: string): string[] {
  return value
    .split(",")
    .map((tag) => tag.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""))
    .filter(Boolean);
}

function blankGenericServiceForm(): GenericServiceFormState {
  return { ...emptyGenericServiceForm, serviceId: undefined, validationProfile: { ...emptyGenericServiceForm.validationProfile } };
}

function genericServiceFormFromPlacement(placement: ServicePlacement | null): GenericServiceFormState {
  if (!placement) {
    return blankGenericServiceForm();
  }
  return {
    serviceId: placement.serviceId,
    name: placement.service || "",
    targetHost: placement.hostId || "proxy01",
    internalPort: placement.port || "18090",
    protocol: placement.protocol || "tcp",
    scriptPath: placement.scriptPath || "",
    purpose: placement.purpose || "",
    tags: placement.tags ?? [],
    notes: placement.notes ?? "",
    validationProfile: placement.validationProfile ?? defaultValidationProfileForGenericProtocol(placement.protocol || "tcp")
  };
}

function mergeGenericServicePlacement(
  operations: EngagementOperationsOverview | null,
  service: GenericServiceActionResult["service"]
): EngagementOperationsOverview | null {
  if (!operations) {
    return operations;
  }
  const placement = genericServicePlacement(service);
  return {
    ...operations,
    servicePlacements: [
      ...operations.servicePlacements.filter((candidate) => candidate.serviceId !== service.serviceId),
      placement
    ]
  };
}

function genericServicePlacement(service: GenericServiceActionResult["service"]): ServicePlacement {
  const config = service.config;
  const targetHost = typeof config.targetHost === "string" ? config.targetHost : service.proxyId;
  const internalPort = config.internalPort;
  const protocol = typeof config.protocol === "string" ? config.protocol : "tcp";
  return {
    hostId: targetHost,
    hostRole: "core",
    service: service.name,
    status: service.status,
    port: typeof internalPort === "number" || typeof internalPort === "string" ? String(internalPort) : "",
    detail: service.status === "Active"
      ? `Operator-managed ${protocol.toUpperCase()} service tracked on ${targetHost}.`
      : `Operator-managed service is ${service.status}.`,
    serviceId: service.serviceId,
    serviceType: service.serviceType,
    protocol,
    transport: typeof config.transport === "string" ? config.transport : normalizedTransport(protocol),
    purpose: typeof config.purpose === "string" ? config.purpose : "",
    scriptPath: typeof config.scriptPath === "string" ? config.scriptPath : "",
    validationProfile: config.validationProfile as InboundValidationProfile | undefined
  };
}

function normalizedTransport(protocol: string): string {
  return ["tcp", "http", "https"].includes(protocol.toLowerCase()) ? "tcp" : protocol.toLowerCase();
}

function mergeWebStaticServicePlacement(
  operations: EngagementOperationsOverview | null,
  service: WebStaticServiceActionResult["service"]
): EngagementOperationsOverview | null {
  if (!operations) {
    return operations;
  }
  const placement = webStaticServicePlacement(service);
  return {
    ...operations,
    servicePlacements: [
      ...operations.servicePlacements.filter((candidate) => candidate.serviceId !== service.serviceId),
      placement
    ]
  };
}

function webStaticServicePlacement(service: WebStaticServiceActionResult["service"]): ServicePlacement {
  const siteName = typeof service.config.siteName === "string" && service.config.siteName ? service.config.siteName : service.name;
  const domain = typeof service.config.domain === "string" ? service.config.domain : "";
  const internalPort = service.config.internalPort;
  return {
    hostId: service.proxyId,
    hostRole: "proxy",
    service: "Static Web",
    status: service.status,
    port: typeof internalPort === "number" || typeof internalPort === "string" ? String(internalPort) : "",
    detail:
      service.status === "Removed"
        ? `Generated config for ${siteName} has been removed. Website files are preserved under /opt/web/${siteName}/html/.`
        : `Static web site ${siteName} is ${service.status.toLowerCase()} on ${service.proxyId}.`,
    serviceId: service.serviceId,
    serviceType: service.serviceType,
    domain,
    siteName
  };
}

function webStaticServicePath(
  service: WebStaticServiceApplyPreview["service"] | WebStaticServiceActionResult["service"],
  key: "contentPath" | "siteConfigPath" | "composePath"
): string {
  const value = service.config[key];
  return typeof value === "string" && value ? value : "N/A";
}

function webStaticJobProgressMessage(job: JobRunDetail): string {
  const lastEvent = job.events[job.events.length - 1];
  return lastEvent ? lastEvent.message : `Static Web job ${job.status}.`;
}

function webStaticJobServiceStatus(job: JobRunDetail): string {
  for (const event of [...job.events].reverse()) {
    const status = event.data?.status;
    if (typeof status === "string" && status.trim()) {
      return status;
    }
    const placements = event.data?.servicePlacements;
    if (Array.isArray(placements)) {
      const placement = placements.find((candidate) => candidate && typeof candidate === "object" && "status" in candidate);
      const placementStatus = placement && typeof placement.status === "string" ? placement.status : "";
      if (placementStatus) {
        return placementStatus;
      }
    }
  }
  return "";
}

function observerJobProgressMessage(job: JobRunDetail): string {
  const latest = job.events[job.events.length - 1];
  return latest ? observerEventLabel(latest.message) : "Inspection is running.";
}

function observerCleanupLabel(job: JobRunDetail | null): string {
  if (!job) {
    return "not run";
  }
  if (job.events.some((event) => event.message === "observer host cleanup verified")) {
    return "verified";
  }
  if (job.events.some((event) => event.message === "inspector host retained")) {
    return "retained";
  }
  if (job.events.some((event) => event.message === "inspector host cleanup verified")) {
    return "verified";
  }
  if (job.events.some((event) => event.message === "observer host cleanup failed")) {
    return "needs attention";
  }
  if (job.events.some((event) => event.message === "inspector host cleanup failed")) {
    return "needs attention";
  }
  if (["queued", "running"].includes(job.status)) {
    return "pending";
  }
  return "not recorded";
}

const inspectorWeekdayOptions = [
  ["mon", "Mon"],
  ["tue", "Tue"],
  ["wed", "Wed"],
  ["thu", "Thu"],
  ["fri", "Fri"],
  ["sat", "Sat"],
  ["sun", "Sun"]
] as const;

function utcTimestampLabel(value: string | null | undefined): string {
  if (!value) {
    return "not scheduled";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "not recorded";
  }
  return parsed.toISOString().replace(".000Z", "Z");
}

function InspectorSettingsPanel({
  engagementId,
  keyedInspectorLinodeOnly,
  observerSettings,
  observerForbiddenPortsInput,
  observerCheckAction,
  providerCatalogs,
  providerCatalogStatus,
  onUpdateObserverSettingsDraft,
  onRetryProviderCatalogs,
  onSaveObserverSettings,
  onEnsureInspectorReadiness,
  onInspectorCleanupComplete,
  onRunObserverCheck,
  setObserverForbiddenPortsInput
}: {
  engagementId: string | null;
  keyedInspectorLinodeOnly: boolean;
  observerSettings: ObserverSettings | null;
  observerForbiddenPortsInput: string;
  observerCheckAction: ObserverCheckActionState;
  providerCatalogs: Record<string, SketchProviderCatalog>;
  providerCatalogStatus: "idle" | "loading" | "ready" | "error";
  onUpdateObserverSettingsDraft: (patch: Partial<Pick<ObserverSettings, "enabled" | "provider" | "region" | "size" | "mode" | "scheduleWeekdays" | "scheduleTimeUtc" | "checkFamilies" | "portScanProfiles">>) => void;
  onRetryProviderCatalogs: () => Promise<Record<string, SketchProviderCatalog>>;
  onSaveObserverSettings: () => void;
  onEnsureInspectorReadiness: () => void;
  onInspectorCleanupComplete: () => Promise<ObserverSettings | null>;
  onRunObserverCheck: () => void;
  setObserverForbiddenPortsInput: (value: string) => void;
}) {
  const [cleanupPreview, setCleanupPreview] = useState<InspectorCleanupPreview | null>(null);
  const [cleanupConfirmation, setCleanupConfirmation] = useState("");
  const [cleanupStatus, setCleanupStatus] = useState<"idle" | "loading" | "running" | "ready" | "error">("idle");
  const [cleanupMessage, setCleanupMessage] = useState("");
  const [cleanupJob, setCleanupJob] = useState<JobRunDetail | null>(null);

  const reviewCleanup = () => {
    if (!engagementId) return;
    setCleanupStatus("loading");
    setCleanupMessage("Reviewing tracked Inspector resources.");
    apiClient.previewInspectorCleanup(engagementId)
      .then((response) => {
        setCleanupPreview(response.preview);
        setCleanupConfirmation("");
        setCleanupStatus("ready");
        setCleanupMessage(response.preview.hosts.length ? "Review the exact Inspector-only cleanup scope." : response.preview.blockers[0] ?? "No Inspector resources are tracked.");
      })
      .catch((error) => {
        setCleanupStatus("error");
        setCleanupMessage(barraganApiErrorSummary(error, "Could not preview Inspector cleanup."));
      });
  };

  const destroyInspector = async () => {
    if (!engagementId || !cleanupPreview) return;
    setCleanupStatus("running");
    setCleanupMessage("Destroying retained Inspector resources.");
    try {
      let response = await apiClient.cleanupInspector(engagementId, cleanupConfirmation);
      let job = response.job;
      setCleanupJob(job);
      for (let attempt = 0; attempt < 120 && ["queued", "running"].includes(job.status); attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 1000));
        job = (await apiClient.job(job.id)).job;
        setCleanupJob(job);
      }
      if (job.status === "succeeded") {
        await onInspectorCleanupComplete();
        setCleanupPreview(null);
        setCleanupConfirmation("");
        setCleanupStatus("ready");
        setCleanupMessage("Inspector resources were destroyed and scheduling was disabled.");
      } else {
        setCleanupStatus("error");
        setCleanupMessage("Inspector cleanup needs attention. Review the job evidence and retry the preview.");
      }
    } catch (error) {
      setCleanupStatus("error");
      setCleanupMessage(barraganApiErrorSummary(error, "Could not destroy the Inspector."));
    }
  };

  if (!observerSettings) {
    return (
      <section className="guided-review" aria-label="Inspector">
        <div className="empty-state inline">
          <h3>Inspector unavailable</h3>
          <p>{observerCheckAction.message || "Open this page after selecting an active engagement."}</p>
        </div>
      </section>
    );
  }

  const profile = observerSettings.portScanProfiles[0] ?? {};
  const scanEnabled = Boolean(profile.enabled);
  const scanTargetGroup = typeof profile.targetGroup === "string" ? profile.targetGroup : "edges";
  const scanPorts = typeof profile.ports === "string" ? profile.ports : "";
  const scanTiming = typeof profile.timing === "string" ? profile.timing : "normal";
  const coreWarningAcknowledged = Boolean(profile.coreTargetWarningAcknowledged);
  const activeHost = observerSettings.currentHost ?? {};
  const unsupportedKeyedInspector = keyedInspectorLinodeOnly && observerSettings.provider === "digitalocean";

  const updateProfile = (patch: Record<string, unknown>) => {
    onUpdateObserverSettingsDraft({
      portScanProfiles: [
        {
          enabled: scanEnabled,
          targetGroup: scanTargetGroup,
          scanMode: "tcp-connect",
          timing: scanTiming,
          ports: scanPorts,
          coreTargetWarningAcknowledged: coreWarningAcknowledged,
          ...patch
        }
      ]
    });
  };
  const toggleWeekday = (weekday: string, checked: boolean) => {
    const next = checked
      ? [...observerSettings.scheduleWeekdays, weekday]
      : observerSettings.scheduleWeekdays.filter((candidate) => candidate !== weekday);
    const ordered = inspectorWeekdayOptions.map(([value]) => value).filter((candidate) => next.includes(candidate));
    onUpdateObserverSettingsDraft({ scheduleWeekdays: ordered });
  };

  return (
    <section className="guided-review" aria-label="Inspector configuration">
      <div className="section-heading">
        <div>
          <h3>Inspector</h3>
          <p className="guardrail-hint">External inspections run from a Barragan-owned helper host. Times are UTC.</p>
        </div>
        <StatusPill value={observerCheckAction.status} />
      </div>
      {providerCatalogStatus === "error" ? (
        <div className="inline-warning" role="alert">
          Provider catalogs could not be loaded. Inspector provider settings remain disabled until authoritative provider data is available.
          <div className="section-actions">
            <button className="secondary-action compact" onClick={() => void onRetryProviderCatalogs()} type="button">
              Retry Provider Catalog
            </button>
          </div>
        </div>
      ) : null}
      {unsupportedKeyedInspector ? (
        <div className="inline-warning" role="alert">
          Keyed infrastructure requires a Linode Inspector. Select Linode before deployment.
        </div>
      ) : null}
      <div className="form-grid compact-form inspector-form">
        <label className="checkbox-row">
          <input
            aria-label="Inspector enabled"
            checked={observerSettings.enabled}
            onChange={(event) => onUpdateObserverSettingsDraft({ enabled: event.target.checked })}
            type="checkbox"
          />
          <span>Enabled</span>
        </label>
        <label className="inspector-size-field">
          <span>Mode</span>
          <select
            aria-label="Inspector mode"
            onChange={(event) => onUpdateObserverSettingsDraft({ mode: event.target.value as ObserverSettings["mode"] })}
            value={observerSettings.mode}
          >
            <option value="once">Once</option>
            <option value="regular">Regular</option>
            <option value="continuous">Continuous</option>
          </select>
        </label>
        <label>
          <span>Provider</span>
          <select
            aria-label="Inspector provider"
            disabled={providerCatalogStatus !== "ready"}
            onChange={(event) => onUpdateObserverSettingsDraft({ provider: event.target.value })}
            value={observerSettings.provider}
          >
            {sketchProviderOptions.map((provider) => (
              <option key={`inspector-provider-${provider}`} value={provider}>{provider}</option>
            ))}
          </select>
        </label>
        <label>
          <span>Region</span>
          <select
            aria-label="Inspector region"
            disabled={providerCatalogStatus !== "ready"}
            onChange={(event) => onUpdateObserverSettingsDraft({ region: event.target.value })}
            value={observerSettings.region}
          >
            {regionOptions(providerCatalogs, observerSettings.provider, observerSettings.region).map((region) => (
              <option disabled={!region.available} key={`inspector-region-${region.id}`} value={region.id}>
                {region.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Size</span>
          <select
            aria-label="Inspector size"
            disabled={providerCatalogStatus !== "ready"}
            onChange={(event) => onUpdateObserverSettingsDraft({ size: event.target.value })}
            value={observerSettings.size}
          >
            {sizeOptions(providerCatalogs, observerSettings.provider, observerSettings.region, observerSettings.size).map((size) => (
              <option disabled={!size.available} key={`inspector-size-${size.id}`} value={size.id}>
                {compactSizeLabel(size)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Schedule time UTC</span>
          <input
            aria-label="Inspector schedule time UTC"
            onChange={(event) => onUpdateObserverSettingsDraft({ scheduleTimeUtc: event.target.value })}
            type="time"
            value={observerSettings.scheduleTimeUtc}
          />
        </label>
        <label>
          <span>Forbidden TCP ports</span>
          <input
            aria-label="Inspector forbidden TCP ports"
            onChange={(event) => setObserverForbiddenPortsInput(event.target.value)}
            placeholder="2222, 5000, 5173"
            value={observerForbiddenPortsInput}
          />
        </label>
      </div>
      <div className="weekday-picker" aria-label="Inspector schedule weekdays">
        {inspectorWeekdayOptions.map(([weekday, label]) => (
          <label key={`inspector-weekday-${weekday}`}>
            <input
              checked={observerSettings.scheduleWeekdays.includes(weekday)}
              onChange={(event) => toggleWeekday(weekday, event.target.checked)}
              type="checkbox"
            />
            <span>{label}</span>
          </label>
        ))}
      </div>
      <details className="advanced-settings-panel compact-advanced">
        <summary>Port Scan Profile</summary>
        <div className="form-grid compact-form">
          <label className="checkbox-row">
            <input
              aria-label="Enable Inspector port scan"
              checked={scanEnabled}
              onChange={(event) => updateProfile({ enabled: event.target.checked })}
              type="checkbox"
            />
            <span>Enable nmap scan</span>
          </label>
          <label>
            <span>Targets</span>
            <select
              aria-label="Inspector port scan targets"
              onChange={(event) => updateProfile({ targetGroup: event.target.value })}
              value={scanTargetGroup}
            >
              <option value="edges">Edges</option>
              <option value="assigned-domains">Assigned domains</option>
              <option value="core-public-management">Core public management IPs</option>
            </select>
          </label>
          <label>
            <span>Ports</span>
            <input
              aria-label="Inspector port scan ports"
              onChange={(event) => updateProfile({ ports: event.target.value })}
              placeholder="80,443,8000-8010"
              value={scanPorts}
            />
          </label>
          <label>
            <span>Pace</span>
            <select aria-label="Inspector port scan pace" onChange={(event) => updateProfile({ timing: event.target.value })} value={scanTiming}>
              <option value="normal">Normal</option>
              <option value="slow">Slow</option>
            </select>
          </label>
          {scanTargetGroup === "core-public-management" ? (
            <label className="checkbox-row">
              <input
                aria-label="Acknowledge core scan OPSEC warning"
                checked={coreWarningAcknowledged}
                onChange={(event) => updateProfile({ coreTargetWarningAcknowledged: event.target.checked })}
                type="checkbox"
              />
              <span>Acknowledge core scan OPSEC warning</span>
            </label>
          ) : null}
        </div>
      </details>
      <div className="workflow-actions">
        <button className="secondary-action" disabled={unsupportedKeyedInspector || providerCatalogStatus !== "ready" || observerCheckAction.status === "saving"} onClick={onSaveObserverSettings} type="button">
          Save Inspector Settings
        </button>
        {observerSettings.enabled && observerSettings.mode === "continuous" ? (
          <button
            className="secondary-action"
            disabled={unsupportedKeyedInspector || providerCatalogStatus !== "ready" || ["running", "saving", "loading"].includes(observerCheckAction.status)}
            onClick={onEnsureInspectorReadiness}
            type="button"
          >
            Verify / Prepare Inspector
          </button>
        ) : null}
        <button
          className="primary-action"
          disabled={unsupportedKeyedInspector || providerCatalogStatus !== "ready" || ["running", "saving", "loading"].includes(observerCheckAction.status)}
          onClick={onRunObserverCheck}
          type="button"
        >
          Run Inspection Now
        </button>
      </div>
      <div className="detail-grid">
        <div>
          <span>Checks</span>
          <strong>Inbound, DNS, TLS, ports</strong>
        </div>
        <div>
          <span>Inspector host</span>
          <strong>{typeof activeHost.publicIp === "string" && activeHost.publicIp ? String(activeHost.publicIp) : "not active"}</strong>
        </div>
        <div>
          <span>Retained until UTC</span>
          <strong>{utcTimestampLabel(observerSettings.idleRetentionUntil)}</strong>
        </div>
        <div>
          <span>Last job</span>
          <strong>{observerCheckAction.job?.id ?? "not run"}</strong>
        </div>
      </div>
      {observerCheckAction.message ? <p className="guardrail-hint">{observerCheckAction.message}</p> : null}
      {observerCheckAction.job ? (
        <div className="job-event-list compact-job-events" aria-label="Inspection events">
          {observerCheckAction.job.events.slice(-6).map((event) => {
            const detail = inspectorEventDetail(event);
            return (
              <div className="job-event" key={`inspection-event-${event.sequence}`}>
                <span>{event.level}</span>
                <div>
                  <strong>{observerEventLabel(event.message)}</strong>
                  {detail ? <p>{detail}</p> : null}
                </div>
              </div>
            );
          })}
        </div>
      ) : null}
      <section className="guided-review inspector-lifecycle" aria-label="Inspector lifecycle">
        <div className="section-heading">
          <div>
            <h4>Inspector lifecycle</h4>
            <p className="guardrail-hint">Retire only the Barragan-owned Inspector host and its provider firewall or tag. Engagement infrastructure and services are not changed.</p>
          </div>
          <StatusPill value={cleanupStatus} />
        </div>
        <div className="workflow-actions">
          <button className="secondary-action" disabled={!engagementId || cleanupStatus === "loading" || cleanupStatus === "running"} onClick={reviewCleanup} type="button">
            Review Inspector Cleanup
          </button>
        </div>
        {cleanupPreview ? (
          <div className="confirmation-panel">
            <p><strong>{cleanupPreview.resourceCount}</strong> tracked resource{cleanupPreview.resourceCount === 1 ? "" : "s"} will be retired.</p>
            {cleanupPreview.hosts.map((host) => (
              <div className="inspector-cleanup-host" key={`${host.provider}-${host.resourceId}`}>
                <div className="detail-grid">
                  <div><span>Inspector</span><strong>{host.name || host.resourceId}</strong></div>
                  <div><span>Provider / region</span><strong>{host.provider} / {host.region || "not recorded"}</strong></div>
                  <div><span>Public IP</span><strong>{host.publicIp || "not recorded"}</strong></div>
                </div>
                {host.associatedResources?.length ? (
                  <details className="compact-advanced">
                    <summary>Provider cleanup details ({host.associatedResources.length})</summary>
                    <ul>
                      {host.associatedResources.map((resource) => (
                        <li key={`${resource.resourceType}-${resource.resourceId}`}>{resource.resourceType}: {resource.name || resource.resourceId}</li>
                      ))}
                    </ul>
                  </details>
                ) : null}
              </div>
            ))}
            {cleanupPreview.blockers.length ? <div className="inline-warning" role="alert">{cleanupPreview.blockers.join(" ")}</div> : null}
            <label>
              <span>Type <code>{cleanupPreview.confirmationToken}</code> to confirm</span>
              <input aria-label="Inspector cleanup confirmation" onChange={(event) => setCleanupConfirmation(event.target.value)} value={cleanupConfirmation} />
            </label>
            <div className="workflow-actions">
              <button
                className="danger-action"
                disabled={!cleanupPreview.canDestroy || cleanupConfirmation !== cleanupPreview.confirmationToken || cleanupStatus === "running"}
                onClick={() => void destroyInspector()}
                type="button"
              >
                Destroy Inspector
              </button>
            </div>
          </div>
        ) : null}
        {cleanupMessage ? <p className="guardrail-hint">{cleanupMessage}</p> : null}
        {cleanupJob ? <p className="guardrail-hint">Job {cleanupJob.id}: {cleanupJob.status}</p> : null}
      </section>
    </section>
  );
}

function observerEventLabel(message: string): string {
  if (message === "inspection queued") {
    return "Inspection queued.";
  }
  if (message === "inspector host create started") {
    return "Creating Inspector host.";
  }
  if (message === "inspector host create succeeded") {
    return "Inspector host is ready.";
  }
  if (message === "inspector host reused") {
    return "Reusing retained Inspector host.";
  }
  if (message === "inspection checks started") {
    return "Running inspection checks.";
  }
  if (message === "inspection checks succeeded") {
    return "Inspection checks passed.";
  }
  if (message === "inspection checks failed") {
    return "Inspection checks found a problem.";
  }
  if (message === "inspector host retained") {
    return "Inspector host retained.";
  }
  if (message === "inspector host cleanup started") {
    return "Tearing down Inspector host.";
  }
  if (message === "inspector host cleanup verified") {
    return "Inspector host cleanup verified.";
  }
  if (message === "inspector host cleanup failed") {
    return "Inspector host cleanup needs attention.";
  }
  if (message === "observer host check queued") {
    return "Queued public connectivity check.";
  }
  if (message === "observer host create started") {
    return "Creating ephemeral observer host.";
  }
  if (message === "observer host create succeeded") {
    return "Observer host is ready.";
  }
  if (message === "observer public checks started") {
    return "Running positive and negative public checks.";
  }
  if (message === "observer public checks succeeded") {
    return "Public checks passed.";
  }
  if (message === "observer public checks failed") {
    return "Public checks found a problem.";
  }
  if (message === "observer host cleanup started") {
    return "Tearing down observer host.";
  }
  if (message === "observer host cleanup verified") {
    return "Observer host cleanup verified.";
  }
  if (message === "observer host cleanup failed") {
    return "Observer host cleanup needs attention.";
  }
  return message;
}

function inspectorEventDetail(event: JobEvent): string {
  const data = recordValue(event.data);
  const errors = arrayValue(data.errors)
    .map((error) => compactUnknownValue(error))
    .filter(Boolean);
  if (errors.length) {
    return errors.slice(0, 2).join(" ");
  }

  const inspectionEvidence = recordValue(data.inspectionEvidence);
  const observerEvidence = recordValue(data.observerEvidence);
  const evidence = Object.keys(inspectionEvidence).length ? inspectionEvidence : observerEvidence;
  const results = arrayValue(evidence.results).map((result) => recordValue(result));
  const failed = results.filter((result) => result.ok === false);
  if (failed.length) {
    const first = failed[0];
    const target = stringValue(first.id) || stringValue(first.type) || "check";
    const observed = compactUnknownValue(first.observed);
    return `${failed.length} check${failed.length === 1 ? "" : "s"} failed: ${target}${observed ? ` - ${observed}` : ""}`;
  }

  return stringValue(data.detail);
}

function compactUnknownValue(value: unknown): string {
  if (value === undefined || value === null || value === "") {
    return "";
  }
  return summaryValue(value);
}

function outboundArtifactTargetRows(channel: OutboundChannelInput, job: JobRunDetail | null): Array<{ name: string; target: string }> {
  const jobTargets = outboundArtifactTargetsFromJob(job);
  if (jobTargets.length) {
    return jobTargets;
  }
  return Object.entries(channel.artifactTargets ?? {}).map(([name, target]) => ({ name, target }));
}

function inboundArtifactTargetRows(channel: InboundChannelInput, job: JobRunDetail | null): Array<{ name: string; target: string }> {
  const jobTargets = inboundArtifactTargetsFromJob(job);
  if (jobTargets.length) {
    return jobTargets;
  }
  return Object.entries(channel.artifactTargets ?? {}).map(([name, target]) => ({ name, target }));
}

function outboundArtifactTargetsFromJob(job: JobRunDetail | null): Array<{ name: string; target: string }> {
  if (!job) {
    return [];
  }
  for (const event of [...job.events].reverse()) {
    const targets = recordValue(event.data.artifactTargets);
    const rows = Object.entries(targets).map(([name, target]) => ({ name, target: String(target) }));
    if (rows.length) {
      return rows;
    }
  }
  return [];
}

function inboundArtifactTargetsFromJob(job: JobRunDetail | null): Array<{ name: string; target: string }> {
  if (!job) {
    return [];
  }
  for (const event of [...job.events].reverse()) {
    const channels = Array.isArray(event.data.inboundChannels) ? event.data.inboundChannels : [];
    for (const channel of channels) {
      const targets = recordValue(recordValue(channel).artifactTargets);
      const rows = Object.entries(targets).map(([name, target]) => ({ name, target: String(target) }));
      if (rows.length) {
        return rows;
      }
    }
  }
  return [];
}

function outboundJobEvidenceSummary(job: JobRunDetail): string {
  const fragments: string[] = [];
  for (const event of job.events) {
    const workspaceEvidence = recordValue(event.data.workspaceEvidence);
    if (Object.keys(workspaceEvidence).length) {
      fragments.push(`workspace evidence: ${Object.keys(workspaceEvidence).join(", ")}`);
    }
    const validationEvidence = recordValue(event.data.validationEvidence);
    if (Object.keys(validationEvidence).length) {
      const status = stringValue(validationEvidence.status) || job.status;
      const observedIp = stringValue(validationEvidence.observedPublicIp);
      const marker = stringValue(validationEvidence.observedMarker) || stringValue(validationEvidence.expectedMarker);
      fragments.push(`validation evidence: ${status}${observedIp ? ` observed ${observedIp}` : ""}${marker ? ` marker ${marker}` : ""}`);
    }
  }
  if (job.artifactRefs.length) {
    fragments.push(`artifacts: ${job.artifactRefs.length}`);
  }
  return fragments.length ? fragments.join("; ") : "job returned without evidence summary";
}

function inboundJobProgressMessage(job: JobRunDetail): string {
  const latestEvent = job.events[job.events.length - 1];
  return latestEvent ? `Inbound job ${job.status}: ${latestEvent.message}` : `Inbound job ${job.status}.`;
}

function downloadTextFile(filename: string, contents: string): void {
  const blob = new Blob([contents], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function recordValue(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function summaryValue(value: unknown): string {
  if (typeof value === "object" && value !== null) {
    return JSON.stringify(value);
  }
  return String(value);
}

function isActiveEngagement(engagement: EngagementSummary | EngagementDetail) {
  return engagement.status !== "archived" && engagement.status !== "retired";
}

function isOperationallyCurrentEngagement(engagement: EngagementSummary | EngagementDetail) {
  return ["active", "deploying", "tearing_down", "cleanup_required", "unknown"].includes(
    engagement.lifecycle?.state ?? ""
  );
}

function engagementLifecycleActionGuidance(engagement: EngagementSummary | EngagementDetail) {
  if (engagement.status === "retired") {
    return "This engagement is retired; no further archive or retire action is available.";
  }
  if (engagement.lifecycle?.terminal === false) {
    switch (engagement.lifecycle.state) {
      case "deploying":
        return "Wait for deployment to finish, then reconcile before archiving or retiring.";
      case "tearing_down":
        return "Wait for teardown verification, then reconcile before archiving or retiring.";
      case "cleanup_required":
        return "Resolve the owned-resource cleanup, then reconcile before archiving or retiring.";
      case "unknown":
        return "Review lifecycle evidence and reconcile before archiving or retiring.";
      default:
        return "Tear down infrastructure and verify cleanup, then reconcile before archiving or retiring.";
    }
  }
  if (engagement.status === "archived") {
    return "This engagement is already archived; Retire remains available.";
  }
  return "";
}

function metadataFromEngagement(engagement: EngagementSummary | EngagementDetail): EngagementMetadataFormState {
  return {
    name: engagement.name,
    owner: engagement.owner,
    description: engagement.description ?? "",
    documentationUrl: engagement.documentationUrl ?? "",
    jiraUrl: engagement.jiraUrl ?? ""
  };
}

function emptyDomainGroups(): DomainGroups {
  return {
    currently_being_used: [],
    waiting_to_be_used: [],
    used_in_past_engagements: []
  };
}

function normalizeDomainGroups(groups: DomainGroups | null | undefined): DomainGroups {
  const source = recordValue(groups);
  return {
    currently_being_used: sortedDomainSummaries(arrayValue(source.currently_being_used) as DomainSummary[]),
    waiting_to_be_used: sortedDomainSummaries(arrayValue(source.waiting_to_be_used) as DomainSummary[]),
    used_in_past_engagements: sortedDomainSummaries(arrayValue(source.used_in_past_engagements) as DomainSummary[])
  };
}

function replaceDomainInGroups(groups: DomainGroups, domain: DomainSummary): DomainGroups {
  const nextBucket = domainBucketKey(domain.bucket);
  const nextGroups = Object.fromEntries(
    domainBucketSections.map((section) => [
      section.key,
      groups[section.key].filter((candidate) => candidate.id !== domain.id)
    ])
  ) as DomainGroups;
  nextGroups[nextBucket] = sortedDomainSummaries([...nextGroups[nextBucket], domain]);
  return nextGroups;
}

function domainBucketKey(value: string): keyof DomainGroups {
  if (value === "currently_being_used" || value === "waiting_to_be_used" || value === "used_in_past_engagements") {
    return value;
  }
  return "waiting_to_be_used";
}

function sortedDomainSummaries(domains: DomainSummary[]): DomainSummary[] {
  return [...domains].sort((left, right) => left.domainName.localeCompare(right.domainName));
}

function domainDnsRecordCount(domain: DomainSummary): number {
  return Number(domain.dnsSummary?.recordCount ?? 0);
}

function normalizedPurposeTags(values: unknown[]): string[] {
  const tags: string[] = [];
  const seen = new Set<string>();
  values.forEach((value) => {
    if (value === null || value === undefined) {
      return;
    }
    const tag = String(value).trim().toLowerCase();
    if (!tag || seen.has(tag)) {
      return;
    }
    seen.add(tag);
    tags.push(tag);
  });
  return tags;
}

function normalizedPurposeTagsFromInput(value: string): string[] {
  return normalizedPurposeTags(value.split(","));
}

function purposeInputValue(purposeTags: string[] | undefined, fallbackPurpose: string): string {
  const tags = normalizedPurposeTags(purposeTags ?? []);
  if (tags.length) {
    return tags.join(", ");
  }
  return fallbackPurpose.trim();
}

function domainConfirmationFromError(error: unknown): DomainConfirmationRequired | null {
  if (!(error instanceof BarraganApiError) || error.status !== 409) {
    return null;
  }
  const confirmation = recordValue(recordValue(error.body).confirmationRequired);
  const token = typeof confirmation.token === "string" ? confirmation.token : "";
  if (!token) {
    return null;
  }
  return {
    required: confirmation.required === true,
    token,
    reasons: arrayValue(confirmation.reasons).map(String)
  };
}

function riskStatusLabel(status: DomainRiskStatus): string {
  const normalized = String(status || "clear").toLowerCase();
  if (normalized === "clear") {
    return "Clear";
  }
  if (normalized === "burned") {
    return "Burned";
  }
  if (normalized === "quarantined") {
    return "Quarantine";
  }
  if (normalized === "cooldown") {
    return "Cooldown";
  }
  return normalized.replace(/[-_]/g, " ");
}

function domainRiskClassName(status: DomainRiskStatus): string {
  const normalized = String(status || "clear").toLowerCase();
  if (normalized === "burned") {
    return "domain-risk-burned";
  }
  if (normalized === "quarantined") {
    return "domain-risk-quarantined";
  }
  if (normalized === "cooldown") {
    return "domain-risk-cooldown";
  }
  return "domain-risk-clear";
}

function formatDomainDate(value?: string | null): string {
  if (!value) {
    return "N/A";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleDateString();
}

function formatDomainDateTime(value?: string | null): string {
  if (!value) {
    return "not synced";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function dnsEditorRecords(domain: EngagementDnsDomain, defaultTtl: number, supportedTypes: string[]): DnsEditorRecord[] {
  const hosts = Array.isArray(domain.dns.hosts) ? domain.dns.hosts : [];
  const supported = new Set(supportedTypes.map((type) => type.toUpperCase()));
  return hosts
    .filter((host) => supported.has(String(host.type || "").toUpperCase()))
    .map((host, index) => ({
      localId: `dns-${domain.id}-${index}`,
      name: host.name || "@",
      type: String(host.type || "A").toUpperCase(),
      address: host.address || "",
      ttl: host.ttl || String(defaultTtl),
      mxPref: host.mxPref || ""
    }));
}

function dnsPreservedRecords(domain: EngagementDnsDomain, supportedTypes: string[]): EngagementDnsRecord[] {
  const hosts = Array.isArray(domain.dns.hosts) ? domain.dns.hosts : [];
  const supported = new Set(supportedTypes.map((type) => type.toUpperCase()));
  return hosts.filter((host) => !supported.has(String(host.type || "").toUpperCase()));
}

function dnsPayloadRecords(records: DnsEditorRecord[], defaultTtl: number): EngagementDnsRecord[] {
  return records.map((record) => ({
    name: record.name.trim() || "@",
    type: String(record.type || "A").trim().toUpperCase(),
    address: record.address.trim(),
    ttl: String(record.ttl || defaultTtl).trim() || String(defaultTtl),
    mxPref: record.type === "MX" ? String(record.mxPref || "10").trim() : ""
  }));
}

function dnsValueSuggestions(recordType: string, edges: EngagementDnsEdgeTarget[]): Array<{ value: string; label: string }> {
  const normalizedType = String(recordType || "").toUpperCase();
  if (!["A", "AAAA", "CNAME", "MX"].includes(normalizedType)) {
    return [];
  }
  return edges
    .map((edge) => {
      const edgeLabel = edge.hostname || edge.label || edge.id;
      const detail = [edge.provider, edge.region, edge.proxy].filter(Boolean).join(" / ");
      const label = detail ? `${edgeLabel} - ${detail}` : edgeLabel;
      if (normalizedType === "A" && isIpv4Address(edge.publicIp)) {
        return { value: edge.publicIp, label };
      }
      if (normalizedType === "AAAA" && isIpv6Address(edge.publicIp)) {
        return { value: edge.publicIp, label };
      }
      if (["CNAME", "MX"].includes(normalizedType) && edge.hostname) {
        return { value: edge.hostname, label: edge.publicIp ? `${label} (${edge.publicIp})` : label };
      }
      return null;
    })
    .filter((suggestion): suggestion is { value: string; label: string } => Boolean(suggestion));
}

function isIpv4Address(value: string): boolean {
  const parts = String(value || "").split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isIpv6Address(value: string): boolean {
  return String(value || "").includes(":");
}

function dnsPreviewHasChanges(preview: EngagementDnsPreview): boolean {
  return Boolean(preview.diff.added.length || preview.diff.updated.length || preview.diff.removed.length);
}

function dnsDiffRows(diff: EngagementDnsDiff): Array<{ kind: string; before?: EngagementDnsRecord; after: EngagementDnsRecord }> {
  const changedRows = [
    ...diff.added.map((record) => ({ kind: "add", after: record })),
    ...diff.updated.map((row) => ({ kind: "update", before: row.before, after: row.after })),
    ...diff.removed.map((record) => ({ kind: "remove", before: record, after: record }))
  ];
  return changedRows.length ? changedRows : diff.unchanged.map((record) => ({ kind: "unchanged", after: record }));
}

function dnsJobProgressMessage(job: JobRunDetail): string {
  const latest = job.events[job.events.length - 1];
  return latest ? `DNS job ${job.status}: ${latest.message}` : `DNS job ${job.status}.`;
}

function standardRtiPreviewInput(
  engagementName = "of02-dev-example",
  sketchIntent: SketchIntentState = defaultSketchIntent,
  templateId = "standard-rti",
  elkEnabled = false,
  deploymentTarget?: DisposableDeploymentReadiness["target"]
) {
  const activeProxies = proxyOptionsForTemplate(templateId);
  const sketchChains = sketchChainsWithIds(sketchIntent.filter((chain) => activeProxies.includes(chain.assignedProxy)));
  return {
    engagementName,
    proxyCount: activeProxies.length,
    elkEnabled: templateId === "small-dev-infra" ? false : elkEnabled,
    ...(deploymentTarget ? {
      deploymentTarget: {
        provider: "oci",
        name: deploymentTarget.name,
        compartmentId: deploymentTarget.compartmentId,
        region: deploymentTarget.region
      }
    } : {}),
    sketchChains: sketchChains.map((chain) => ({
      id: chain.id,
      assignedProxy: chain.assignedProxy,
      middleProvider: chain.middleProvider,
      edgeProvider: chain.edgeProvider,
      middleRegion: chain.middleRegion,
      edgeRegion: chain.edgeRegion,
      middleSize: chain.middleSize,
      edgeSize: chain.edgeSize,
      edgeCount: chain.edges.length,
      edges: chain.edges
    })),
    egressProfiles: sketchChains.map((chain, index) => ({
      name: index === 0 ? "default-sketch-egress" : `sketch-egress-${index + 1}`,
      sketchChainId: chain.id,
      listenerPort: 3333 + index
    })),
    ingressRoutes: sketchChains.map((chain, index) => ({
      name: index === 0 ? "default-ingress" : `ingress-${index + 1}`,
      sketchChainId: chain.id,
      domain: index === 0 ? "example.invalid" : `${chain.id}.example.invalid`
    })),
    reverseChannels: []
  };
}

function sketchIntentFromInputParameters(parameters: Record<string, unknown>): SketchIntentState | null {
  const rawChains = parameters.sketchChains;
  if (!Array.isArray(rawChains)) return null;
  const chains: SketchIntentState = [];
  for (const rawChain of rawChains) {
    if (!rawChain || typeof rawChain !== "object") return null;
    const chain = rawChain as Record<string, unknown>;
    const fields = ["assignedProxy", "middleProvider", "middleRegion", "middleSize", "edgeProvider", "edgeRegion", "edgeSize"] as const;
    if (fields.some((field) => typeof chain[field] !== "string" || !chain[field])) return null;
    if (!Array.isArray(chain.edges)) return null;
    const edges: SketchIntentState[number]["edges"] = [];
    for (const rawEdge of chain.edges) {
      if (!rawEdge || typeof rawEdge !== "object") return null;
      const edge = rawEdge as Record<string, unknown>;
      if (["id", "provider", "region", "size"].some((field) => typeof edge[field] !== "string" || !edge[field])) return null;
      edges.push({ id: edge.id as string, provider: edge.provider as string, region: edge.region as string, size: edge.size as string });
    }
    chains.push({
      assignedProxy: chain.assignedProxy as string,
      middleProvider: chain.middleProvider as string,
      middleRegion: chain.middleRegion as string,
      middleSize: chain.middleSize as string,
      edgeProvider: chain.edgeProvider as string,
      edgeRegion: chain.edgeRegion as string,
      edgeSize: chain.edgeSize as string,
      edgeCount: edges.length,
      edges
    });
  }
  return chains;
}

function sketchChainsWithIds(sketchIntent: SketchIntentState) {
  const proxyChainCounts = Object.fromEntries(proxyOptions.map((proxy) => [proxy, 0])) as Record<string, number>;
  return sketchIntent.map((chain, sourceIndex) => {
    const assignedProxy = proxyOptions.includes(chain.assignedProxy) ? chain.assignedProxy : proxyOptions[0];
    proxyChainCounts[assignedProxy] = (proxyChainCounts[assignedProxy] ?? 0) + 1;
    return {
      ...chain,
      assignedProxy,
      id: `${assignedProxy}-chain-${proxyChainCounts[assignedProxy]}`,
      sourceIndex
    };
  });
}

function compiledRevisionSketchChains(revision: DeploymentRevision): SketchChainWithId[] {
  const rawChains = revision.inputParameters.sketchChains;
  if (!Array.isArray(rawChains)) return [];
  return rawChains.flatMap((rawChain, sourceIndex) => {
    if (!rawChain || typeof rawChain !== "object") return [];
    const chain = rawChain as Record<string, unknown>;
    const edges = Array.isArray(chain.edges) ? chain.edges.flatMap((rawEdge, edgeIndex) => {
      if (!rawEdge || typeof rawEdge !== "object") return [];
      const edge = rawEdge as Record<string, unknown>;
      const provider = typeof edge.provider === "string" ? edge.provider : "";
      const region = typeof edge.region === "string" ? edge.region : "";
      const size = typeof edge.size === "string" ? edge.size : "";
      if (!provider || !region || !size) return [];
      return [{ id: typeof edge.id === "string" ? edge.id : `edge-${String(edgeIndex + 1).padStart(2, "0")}`, provider, region, size }];
    }) : [];
    const assignedProxy = typeof chain.assignedProxy === "string" ? chain.assignedProxy : "";
    const middleProvider = typeof chain.middleProvider === "string" ? chain.middleProvider : "";
    const middleRegion = typeof chain.middleRegion === "string" ? chain.middleRegion : "";
    const middleSize = typeof chain.middleSize === "string" ? chain.middleSize : "";
    const edgeProvider = typeof chain.edgeProvider === "string" ? chain.edgeProvider : "";
    const edgeRegion = typeof chain.edgeRegion === "string" ? chain.edgeRegion : "";
    const edgeSize = typeof chain.edgeSize === "string" ? chain.edgeSize : "";
    if (!assignedProxy || !middleProvider || !middleRegion || !middleSize || !edgeProvider || !edgeRegion || !edgeSize || !edges.length) return [];
    return [{
      id: typeof chain.id === "string" ? chain.id : `${assignedProxy}-chain-${sourceIndex + 1}`,
      sourceIndex,
      assignedProxy,
      middleProvider,
      middleRegion,
      middleSize,
      edgeProvider,
      edgeRegion,
      edgeSize,
      edges,
      edgeCount: edges.length
    }];
  });
}

function isDeployableSketchChain(chain: SketchChainWithId): boolean {
  return ["linode", "digitalocean"].includes(chain.middleProvider)
    && chain.edges.length > 0
    && chain.edges.every((edge) => ["linode", "digitalocean"].includes(edge.provider) && Boolean(edge.region) && Boolean(edge.size));
}

function sketchChainSummary(chains: SketchChainWithId[]): string {
  if (chains.length === 1) {
    const chain = chains[0];
    return `${chain.id}: ${chain.assignedProxy} -> ${chain.middleProvider} middle -> ${chain.edges.map((edge) => `${edge.id} ${edge.provider}/${edge.region}`).join(", ")}`;
  }
  return `${chains.length} sketch chains (${chains.map((chain) => `${chain.assignedProxy}:${chain.middleProvider}->${chain.edges.map((edge) => edge.provider).join("+")}`).join(", ")})`;
}

function providerSummary(chains: SketchChainWithId[]): string {
  const providers = [...new Set(chains.flatMap((chain) => [chain.middleProvider, ...chain.edges.map((edge) => edge.provider)]))];
  return providers.length ? providers.join(", ") : "N/A";
}

function sketchChainRequest(chain: SketchIntentState[number] & { id?: string; sourceIndex?: number }) {
  return {
    assignedProxy: chain.assignedProxy,
    middleProvider: chain.middleProvider,
    middleRegion: chain.middleRegion,
    middleSize: chain.middleSize,
    edgeProvider: chain.edgeProvider,
    edgeRegion: chain.edgeRegion,
    edgeSize: chain.edgeSize,
    edgeCount: chain.edges.length,
    edges: chain.edges
  };
}

function resizeEdgeIntents(chain: SketchIntentState[number], count: number) {
  const edges = chain.edges.slice(0, count);
  while (edges.length < count) {
    const next = edges.length + 1;
    edges.push({ id: `edge-${String(next).padStart(2, "0")}`, provider: chain.edgeProvider, region: chain.edgeRegion, size: chain.edgeSize });
  }
  return { edges, edgeCount: edges.length, edgeProvider: edges[0].provider, edgeRegion: edges[0].region, edgeSize: edges[0].size };
}

function replaceEdgeIntent(chain: SketchIntentState[number], index: number, patch: Partial<SketchIntentState[number]["edges"][number]>) {
  const edges = chain.edges.map((edge, edgeIndex) => edgeIndex === index ? { ...edge, ...patch } : edge);
  return { edges, edgeCount: edges.length, edgeProvider: edges[0].provider, edgeRegion: edges[0].region, edgeSize: edges[0].size };
}

function effectiveSketchChainEdges(
  chain: Pick<SketchChainRecord, "edgeProvider" | "edgeRegion" | "edgeSize" | "edgeCount" | "edges">
): SketchChainRecord["edges"] {
  return chain.edges?.length
    ? chain.edges
    : Array.from({ length: chain.edgeCount }, (_, index) => ({
      id: `edge-${String(index + 1).padStart(2, "0")}`,
      provider: chain.edgeProvider,
      region: chain.edgeRegion,
      size: chain.edgeSize
    }));
}

function replaceEffectiveSketchEdge(
  chain: Pick<SketchChainRecord, "edgeProvider" | "edgeRegion" | "edgeSize" | "edgeCount" | "edges">,
  index: number,
  patch: Partial<SketchChainRecord["edges"][number]>
): SketchChainRecord["edges"] {
  return effectiveSketchChainEdges(chain).map((edge, edgeIndex) => edgeIndex === index ? { ...edge, ...patch } : edge);
}

function updateEffectiveSketchEdge(
  chain: Pick<SketchChainRecord, "edgeProvider" | "edgeRegion" | "edgeSize" | "edgeCount" | "edges">,
  index: number,
  patch: Partial<SketchChainRecord["edges"][number]>
) {
  const edges = replaceEffectiveSketchEdge(chain, index, patch);
  return { edges, edgeProvider: edges[0].provider, edgeRegion: edges[0].region, edgeSize: edges[0].size };
}

function matchingDurableChainByShape(chains: SketchChainRecord[], chain: SketchChainWithId): SketchChainRecord | null {
  return (
    chains.find(
      (record) =>
        record.assignedProxy === chain.assignedProxy &&
        record.middleProvider === chain.middleProvider &&
        record.middleRegion === chain.middleRegion &&
        record.edgeProvider === chain.edgeProvider &&
        record.edgeRegion === chain.edgeRegion &&
        record.edgeCount === chain.edgeCount &&
        sameEdgeIntent(record, chain.edges) &&
        !["destroyed", "aborted"].includes(record.status)
    ) ?? null
  );
}

function matchingDeployableDurableChain(chains: SketchChainRecord[], chain: SketchChainWithId): SketchChainRecord | null {
  return (
    chains.find(
      (record) =>
        ["pending", "failed"].includes(record.status) &&
        record.assignedProxy === chain.assignedProxy &&
        record.middleProvider === chain.middleProvider &&
        record.middleRegion === chain.middleRegion &&
        record.edgeProvider === chain.edgeProvider &&
        record.edgeRegion === chain.edgeRegion &&
        record.edgeCount === chain.edgeCount &&
        sameEdgeIntent(record, chain.edges)
    ) ?? null
  );
}

function sameEdgeIntent(
  record: SketchChainRecord,
  draftEdges: SketchIntentState[number]["edges"]
): boolean {
  const normalizedRecord = record.edges?.length
    ? record.edges
    : Array.from({ length: record.edgeCount }, (_, index) => ({
      id: `edge-${String(index + 1).padStart(2, "0")}`,
      provider: record.edgeProvider,
      region: record.edgeRegion,
      size: record.edgeSize
    }));
  return normalizedRecord.length === draftEdges.length && normalizedRecord.every((edge, index) => {
    const draft = draftEdges[index];
    return edge.id === draft.id && edge.provider === draft.provider && edge.region === draft.region && edge.size === draft.size;
  });
}

function jobForSketchChain(
  jobs: JobRunDetail[],
  durableChain: SketchChainRecord | null,
  chain: SketchChainWithId
): JobRunDetail | null {
  return (
    jobs.find((job) => String(job.input.chainId ?? "") === durableChain?.chainId) ??
    jobs.find((job) => String(job.input.assignedProxy ?? "") === chain.assignedProxy && String(job.action).includes("sketch")) ??
    null
  );
}

function upsertJobDetail(jobs: JobRunDetail[], job: JobRunDetail | undefined | null): JobRunDetail[] {
  if (!job) {
    return jobs;
  }
  return [job, ...jobs.filter((candidate) => candidate.id !== job.id)];
}

function upsertJobSummary(jobs: JobRunSummary[], job: JobRunDetail): JobRunSummary[] {
  const summary = {
    id: job.id,
    action: job.action,
    status: job.status,
    target: `${job.targetType}:${job.targetId}`,
    createdAt: new Date().toISOString()
  };
  return [summary, ...jobs.filter((candidate) => candidate.id !== job.id)];
}

function upsertSketchChain(chains: SketchChainRecord[], chain: SketchChainRecord | undefined | null): SketchChainRecord[] {
  if (!chain) {
    return chains;
  }
  const existing = chains.some((candidate) => candidate.chainId === chain.chainId);
  if (existing) {
    return chains.map((candidate) => (candidate.chainId === chain.chainId ? chain : candidate));
  }
  return [...chains, chain];
}

function sketchOutboundAutoConfigMessage(result: {
  outboundApply?: { status?: string; errors?: string[] } | null;
  outboundValidation?: { status?: string } | null;
}): string {
  if (result.outboundApply?.status === "Auto Configuration Failed") {
    const detail = result.outboundApply.errors?.length ? `: ${result.outboundApply.errors.join("; ")}` : ".";
    return `Outbound channel setup failed${detail}`;
  }
  return "";
}

function providerCatalog(catalogs: Record<string, SketchProviderCatalog>, provider: string): SketchProviderCatalog {
  return catalogs[provider] ?? seededProviderCatalogs[provider] ?? seededProviderCatalogs.linode;
}

function providerDefaults(catalogs: Record<string, SketchProviderCatalog>, provider: string): { region: string; size: string } {
  const catalog = providerCatalog(catalogs, provider);
  return {
    region: catalog.defaults.region || catalog.regions.find((region) => region.available)?.id || "",
    size: catalog.defaults.size || catalog.sizes.find((size) => size.available)?.id || ""
  };
}

function regionOptions(
  catalogs: Record<string, SketchProviderCatalog>,
  provider: string,
  selectedRegion: string
): SketchProviderCatalog["regions"] {
  const catalog = providerCatalog(catalogs, provider);
  return catalog.regions.filter((region) => region.available || region.id === selectedRegion);
}

function regionOptionsWithCurrentPolicyMarker(
  catalogs: Record<string, SketchProviderCatalog>,
  provider: string,
  selectedRegion: string
): SketchProviderCatalog["regions"] {
  const options = regionOptions(catalogs, provider, selectedRegion);
  if (!selectedRegion || options.some((region) => region.id === selectedRegion)) {
    return options;
  }
  return [
    {
      id: selectedRegion,
      label: `${selectedRegion} (not allowed)`,
      available: false
    },
    ...options
  ];
}

function sizeOptions(
  catalogs: Record<string, SketchProviderCatalog>,
  provider: string,
  region: string,
  selectedSize: string
): SketchProviderCatalog["sizes"] {
  const catalog = providerCatalog(catalogs, provider);
  const available = catalog.sizes.filter((size) => sizeAvailableInRegion(size, region));
  return ensureSelectedOption(available.length ? available : catalog.sizes, selectedSize) as SketchProviderCatalog["sizes"];
}

function sizeForRegion(
  catalogs: Record<string, SketchProviderCatalog>,
  provider: string,
  region: string,
  currentSize: string
): string {
  const options = sizeOptions(catalogs, provider, region, currentSize).filter((size) => size.available);
  if (options.some((size) => size.id === currentSize && sizeAvailableInRegion(size, region))) {
    return currentSize;
  }
  const defaults = providerDefaults(catalogs, provider);
  if (options.some((size) => size.id === defaults.size)) {
    return defaults.size;
  }
  return options[0]?.id ?? currentSize;
}

function sizeAvailableInRegion(size: SketchProviderCatalog["sizes"][number], region: string): boolean {
  if (!region) {
    return false;
  }
  const regions = size.regions ?? [];
  return size.available && (!regions.length || regions.includes(region));
}

function sketchChainRegionPolicyErrors(
  chain: Pick<SketchChainRecord, "middleProvider" | "middleRegion" | "edgeProvider" | "edgeRegion" | "edgeSize" | "edgeCount" | "edges">,
  catalogs: Record<string, SketchProviderCatalog>
): string[] {
  const checks = [
    { label: "middle", provider: chain.middleProvider, region: chain.middleRegion },
    ...effectiveSketchChainEdges(chain).map((edge, index) => ({
      label: chain.edgeCount > 1 ? `edge ${String(index + 1).padStart(2, "0")}` : "edge",
      provider: edge.provider,
      region: edge.region
    }))
  ];
  return checks
    .filter((check) => !regionAllowedByCatalog(catalogs, check.provider, check.region))
    .map((check) => `${check.label} ${check.provider}/${check.region}`);
}

function regionAllowedByCatalog(
  catalogs: Record<string, SketchProviderCatalog>,
  provider: string,
  region: string
): boolean {
  if (!region) {
    return false;
  }
  const catalog = providerCatalog(catalogs, provider);
  return catalog.regions.some((candidate) => candidate.id === region && candidate.available);
}

function sizeLabel(size: SketchProviderCatalog["sizes"][number]): string {
  const parts = [
    size.label || size.id,
    size.vcpus ? `${size.vcpus} vCPU` : null,
    size.memoryMb ? `${Math.round(size.memoryMb / 1024)} GB RAM` : null,
    size.priceMonthly ? `$${size.priceMonthly}/mo` : null
  ].filter(Boolean);
  return parts.join(" · ");
}

function compactSizeLabel(size: SketchProviderCatalog["sizes"][number]): string {
  const parts = [
    size.id || size.label,
    size.vcpus ? `${size.vcpus} vCPU` : null,
    size.memoryMb ? `${Math.round(size.memoryMb / 1024)} GB` : null
  ].filter(Boolean);
  return parts.join(" · ");
}

function ensureSelectedOption<T extends { id: string; label: string; available: boolean }>(options: T[], selectedId: string): T[] {
  if (!selectedId || options.some((option) => option.id === selectedId)) {
    return options;
  }
  return [{ id: selectedId, label: `${selectedId} (not in catalog)`, available: false } as T, ...options];
}

function TableHeader({ columns }: { columns: string[] }) {
  return (
    <div className="table-header">
      {columns.map((column) => (
        <span key={column}>{column}</span>
      ))}
    </div>
  );
}

function OperationsEmptyState({ message }: { message: string }) {
  return (
    <div className="table-row operations-empty-row">
      <span>{message}</span>
    </div>
  );
}

function HostValueField({
  label,
  onChange,
  options,
  placeholder,
  value
}: {
  label: string;
  onChange: (value: string) => void;
  options: HostOption[];
  placeholder: string;
  value: string;
}) {
  const choices = withCurrentHostOption(options, value);
  if (!choices.length) {
    return (
      <label>
        {label}
        <input
          aria-label={label}
          onChange={(event) => onChange(event.target.value)}
          placeholder={placeholder}
          value={value}
        />
      </label>
    );
  }
  return (
    <label>
      {label}
      <select aria-label={label} onChange={(event) => onChange(event.target.value)} value={value}>
        <option value="">Select {label.toLowerCase()}</option>
        {choices.map((option) => (
          <option key={`${label}-${option.value}`} value={option.value}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

function InboundIngressAssessmentPanel({ assessment }: { assessment: InboundIngressAssessment }) {
  return (
    <div className={`ingress-assessment-panel ${assessment.applyAllowed ? "ready" : "blocked"}`}>
      <div className="ingress-assessment-heading">
        <div>
          <span>Ingress readiness</span>
          <p>{assessment.summary}</p>
        </div>
        <StatusPill value={assessment.applyAllowed ? "apply allowed" : "blocked"} />
      </div>
      {assessment.blockingReasons.length ? (
        <div className="inline-warning" role="status">
          {assessment.blockingReasons.join(" ")}
        </div>
      ) : null}
      <div className="ingress-check-list">
        {assessment.checks.map((check) => (
          <div className="ingress-check-row" key={check.id}>
            <div>
              <strong>{check.label}</strong>
              <span>
                {check.host} · {check.port}/{check.protocol}
                {check.source ? ` · from ${check.source}` : ""}
              </span>
            </div>
            <StatusPill value={check.status} />
            <p>
              {check.detail}
              {check.correctiveAction ? ` ${check.correctiveAction}` : ""}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

function InboundValidationStatus({ channel }: { channel: EngagementOperationsOverview["inboundChannels"][number] }) {
  return (
    <div className="validation-status-stack" aria-label={`${channel.channelId} validation status`}>
      <div>
        <span>Route validation</span>
        <StatusPill value={inboundRouteValidationStatus(channel)} />
      </div>
      <div>
        <span>Public ingress</span>
        <StatusPill value={inboundPublicIngressStatus(channel)} />
      </div>
    </div>
  );
}

function ManagedRouteDetails({ engagementId, channelId }: { engagementId: string; channelId: string }) {
  const [state, setState] = useState<{
    status: "idle" | "loading" | "loaded" | "error";
    value: InboundManagedRuntime | null;
    message: string;
  }>({ status: "idle", value: null, message: "" });

  const load = () => {
    if (state.status === "loading") return;
    setState({ status: "loading", value: null, message: "" });
    void apiClient.inboundManagedRuntime(engagementId, channelId).then(
      (value) => setState({ status: "loaded", value, message: "" }),
      (error: unknown) => setState({
        status: "error",
        value: null,
        message: error instanceof Error ? error.message : "Managed route details could not be loaded."
      })
    );
  };
  const value = state.value;
  const path = value
    ? [value.selectedPath.edge, value.selectedPath.middle, value.selectedPath.proxy].filter(Boolean).join(" → ")
    : "";
  return (
    <details
      className="managed-route-disclosure compact-advanced"
      onToggle={(event) => {
        if (event.currentTarget.open) load();
      }}
    >
      <summary>Managed route details</summary>
      {state.status === "loading" ? <p role="status">Loading managed route details…</p> : null}
      {state.status === "error" ? <p className="inline-alert error" role="alert">{state.message}</p> : null}
      {value ? (
        <div className="managed-route-details">
          <p className="guardrail-hint">Read-only Barragan-managed runtime. Change this route through the channel workflow.</p>
          <div className="detail-grid compact-detail-grid">
            <div><span>Route</span><strong>{value.routeId}</strong></div>
            <div><span>Routing owner</span><strong>{value.routingOwner.label}</strong></div>
            <div><span>Selected chain</span><strong>{value.selectedPath.chainId || "Legacy record"}</strong></div>
            <div><span>Path</span><strong>{path || "Partially recorded"}</strong></div>
            <div><span>External listener</span><strong>{value.externalListener.host || "Unknown"}:{value.externalListener.port || "?"}/{value.externalListener.protocol.toLowerCase()}</strong></div>
            <div><span>Termination</span><strong>{value.termination.host || "Unknown"}:{value.termination.port || "?"}</strong></div>
            <div><span>Validation</span><strong>{String(value.validation.status || "Not recorded")}</strong></div>
            <div><span>Latest job</span><strong>{value.latestJob ? `${value.latestJob.id} · ${value.latestJob.status}` : "Not recorded"}</strong></div>
          </div>
          {value.site ? (
            <div className="managed-route-section">
              <h4>Managed web site</h4>
              <p>{value.site.domain || "Unrecorded host"} → {value.site.serviceName}:{value.site.containerPort} → {value.site.backend.host || value.site.backend.kind}:{value.site.backend.port || "content"}</p>
              <p>Certificate: {value.certificate?.status ? String(value.certificate.status) : "Not bound"}</p>
            </div>
          ) : null}
          {value.failClosedDefault ? (
            <p className="guardrail-hint"><strong>{value.failClosedDefault.target}</strong> — {value.failClosedDefault.detail}</p>
          ) : null}
          <div className="managed-route-section">
            <h4>Managed artifacts</h4>
            {value.managedArtifacts.length ? (
              <ul className="managed-route-artifacts">
                {value.managedArtifacts.map((artifact) => <li key={`${artifact.scope}-${artifact.path}`}><span>{artifact.scope}</span><code>{artifact.path}</code></li>)}
              </ul>
            ) : <p>{value.artifactStatus}</p>}
          </div>
        </div>
      ) : null}
    </details>
  );
}

function CertificateStatusPanel({ certificate }: { certificate: InboundChannelCertificate | null }) {
  if (!certificate?.type) {
    return <p className="guardrail-hint">No certificate is associated with this HTTPS inbound channel yet.</p>;
  }
  return (
    <section className="certificate-status-panel" aria-label="Certificate status">
      <div className="detail-grid compact-detail-grid">
        <div>
          <span>Type</span>
          <strong>{certificate.type}</strong>
        </div>
        <div>
          <span>Status</span>
          <strong>{certificate.status || "Recorded"}</strong>
        </div>
        <div>
          <span>Expires</span>
          <strong>{formatOperationsTimestamp(certificate.expiresAt)}</strong>
        </div>
        <div>
          <span>Domain</span>
          <strong>{certificate.domain || "N/A"}</strong>
        </div>
      </div>
      {certificate.paths ? (
        <div className="certificate-paths">
          <span>Certificate paths</span>
          {certificate.paths.liveDir ? <code>{certificate.paths.liveDir}</code> : null}
          {certificate.paths.fullchain ? <code>{certificate.paths.fullchain}</code> : null}
          {certificate.paths.privkey ? <code>{certificate.paths.privkey}</code> : null}
        </div>
      ) : null}
    </section>
  );
}

function CertificatePrerequisitesPanel({ prerequisites }: { prerequisites: InboundChannelCertificatePrerequisites | null }) {
  if (!prerequisites) {
    return <p className="guardrail-hint">Certificate prerequisites are loading.</p>;
  }
  return (
    <section className="certificate-prereq-panel" aria-label="Certificate prerequisites">
      <div className="section-heading compact-heading">
        <div>
          <h4>Let&apos;s Encrypt readiness</h4>
          <p>{prerequisites.summary}</p>
        </div>
        <StatusPill value={prerequisites.status} />
      </div>
      <div className="certificate-prereq-list">
        {prerequisites.checks.map((check) => (
          <div className="ingress-check-row" key={check.id}>
            <div>
              <strong>{check.label}</strong>
              <span>{check.detail}</span>
            </div>
            <StatusPill value={check.status} />
          </div>
        ))}
      </div>
    </section>
  );
}

function InboundPublicIngressPolicyHint({
  channel,
  operations
}: {
  channel: InboundChannelFormState;
  operations: EngagementOperationsOverview | null;
}) {
  const policy = inboundPublicIngressPolicy(operations, channel);
  return (
    <div className={`ingress-policy-hint ${policy.level}`} aria-label="Inbound public ingress policy">
      <div className="ingress-policy-hint-heading">
        <div>
          <span>Public ingress policy</span>
          <strong>{policy.title}</strong>
        </div>
        <StatusPill value={policy.status} />
      </div>
      <p>{policy.detail}</p>
      <div className="ingress-policy-facts">
        <div>
          <span>Edge</span>
          <strong>{policy.edgeLabel}</strong>
        </div>
        <div>
          <span>Provider</span>
          <strong>{policy.providerLabel}</strong>
        </div>
        <div>
          <span>Standard TCP ports</span>
          <strong>{policy.standardPorts}</strong>
        </div>
      </div>
    </div>
  );
}

function HealthBadge({ health }: { health: { status: string; stale?: boolean; detail?: string } }) {
  const label = health.stale ? `${health.status} · stale` : health.status;
  return <span className={`status-pill ${statusClassName(health.status)}`} title={health.detail}>{label}</span>;
}

function StatusPill({ value }: { value: string }) {
  return <span className={`status-pill ${statusClassName(value)}`}>{value.replaceAll("_", " ")}</span>;
}

function inboundChannelSupportsCertificate(channel: EngagementOperationsOverview["inboundChannels"][number]): boolean {
  return operationValue(channel.mode, "").toLowerCase() === "https-openresty" && operationValue(channel.protocol, "").toUpperCase() === "HTTPS";
}

function inboundChannelSupportsRequestHeaderGate(channel: EngagementOperationsOverview["inboundChannels"][number]): boolean {
  const mode = operationValue(channel.mode, "").toLowerCase();
  const protocol = operationValue(channel.protocol, "").toUpperCase();
  const status = operationValue(channel.status, "").toLowerCase();
  if (!new Set(["applied", "pending validation", "validated", "validation failed", "validated with warnings"]).has(status)) {
    return false;
  }
  if (mode === "http-openresty" && protocol === "HTTP") {
    return true;
  }
  return mode === "https-openresty" &&
    protocol === "HTTPS" &&
    new Set(["web-static", "web-http-backend"]).has(operationValue(channel.serviceType, "").toLowerCase()) &&
    Boolean(operationValue(channel.serviceId, ""));
}

function requestHeaderGateFormReady(action: InboundRequestHeaderGateActionState): boolean {
  if (!action.workspace || action.status === "loading" || action.status === "running") {
    return false;
  }
  if (!requestHeaderGateMaxBodyIsValid(action.maxRequestBodyMb, action.workspace.backendPolicy?.maxRequestBodyMb)) {
    return false;
  }
  if (action.workspace.backendPolicy?.capabilityId === "go-simple-upload-server") {
    return false;
  }
  if (!action.enabled) {
    return true;
  }
  return requestHeaderGateHeaderIsValid(action.headerName) && requestHeaderGateProvidedTokenIsValid(action.token);
}

function requestHeaderGateMaxBodyIsValid(value: string, maximum = 10240): boolean {
  if (!/^\d+$/.test(value)) {
    return false;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 1 && parsed <= maximum;
}

function requestHeaderGateHeaderIsValid(value: string): boolean {
  const header = value.trim();
  if (!/^[A-Za-z][A-Za-z0-9-]{0,63}$/.test(header)) {
    return false;
  }
  return !new Set([
    "connection",
    "content-length",
    "expect",
    "host",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade"
  ]).has(header.toLowerCase());
}

function requestHeaderGateProvidedTokenIsValid(value: string): boolean {
  return value.length >= 8 && value.length <= 20 && /^[A-Za-z0-9._~+/=-]+$/.test(value);
}

function generateRequestGateToken(): string {
  const bytes = new Uint8Array(15);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function requestHeaderGateDraftCurl(workspace: InboundRequestHeaderGateWorkspace, headerName: string, token: string): string {
  if (!requestHeaderGateHeaderIsValid(headerName) || !requestHeaderGateProvidedTokenIsValid(token)) {
    return "";
  }
  if (workspace.authorizedRequest.curl) {
    return workspace.authorizedRequest.curl.replace(
      /--header '[^'\r\n]+: Bearer [^'\r\n]*'/,
      `--header '${headerName.trim()}: Bearer ${token}'`
    );
  }

  const channel = workspace.channel;
  const domain = channel.domain?.trim() ?? "";
  const externalPort = channel.externalPort?.trim() ?? "";
  if (!domain || !externalPort) {
    return "";
  }
  const edgeAddress = workspace.edgePublicIp?.trim() ?? "";
  if (!edgeAddress) {
    return "";
  }
  const header = `--header '${headerName.trim()}: Bearer ${token}'`;
  const parts = ["curl --include --request GET"];
  if (channel.mode?.trim().toLowerCase() === "https-openresty") {
    const authority = externalPort === "443" ? domain : `${domain}:${externalPort}`;
    if (edgeAddress !== domain) {
      parts.push(`--resolve '${domain}:${externalPort}:${edgeAddress}'`);
    }
    parts.push(header, `'https://${authority}/'`);
  } else {
    const endpoint = externalPort === "80" ? edgeAddress : `${edgeAddress}:${externalPort}`;
    parts.push(`--header 'Host: ${domain}'`, header, `'http://${endpoint}/'`);
  }
  return parts.join(" \\\n  ");
}

function requestHeaderGateJobProgressMessage(job: JobRunDetail): string {
  const latest = job.events[job.events.length - 1];
  const detail = latest ? channelConsoleEventText(latest) : "Waiting for the first progress event.";
  if (job.status === "queued") {
    return `Request access job queued. ${detail}`;
  }
  if (job.status === "running") {
    return `Request access job running. ${detail}`;
  }
  if (job.status === "succeeded") {
    return `Request access policy applied. ${detail}`;
  }
  return `Request access job ${job.status}. ${detail}`;
}

function certificateIssueAllowed(action: InboundCertificateActionState): boolean {
  if (action.status === "running" || action.status === "loading") {
    return false;
  }
  if (action.certificateType === "self-signed") {
    const domainReady = action.workspace?.prerequisites.checks.find((check) => check.id === "domain-present")?.status === "ready";
    const assignmentReady = action.workspace?.prerequisites.checks.find((check) => check.id === "domain-assigned")?.status === "ready";
    return Boolean(domainReady && assignmentReady);
  }
  const emailReady = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(action.acmeEmail.trim());
  return Boolean(action.workspace?.prerequisites.ready && emailReady && certificateProductionConfirmed(action));
}

function certificateProductionConfirmationToken(action: InboundCertificateActionState): string {
  if (action.certificateType !== "letsencrypt" || action.acmeEnvironment !== "production") {
    return "";
  }
  const channelId = action.activeChannelId?.trim();
  const domain = action.workspace?.channel.domain?.trim().toLowerCase();
  return channelId && domain ? `issue-production-${channelId}-${domain}` : "";
}

function certificateProductionConfirmed(action: InboundCertificateActionState): boolean {
  const expected = certificateProductionConfirmationToken(action);
  return !expected || action.productionConfirmation === expected;
}

function certificateJobIsRunning(job: JobRunDetail): boolean {
  return job.status === "queued" || job.status === "running";
}

function certificateJobProgressMessage(job: JobRunDetail): string {
  const latest = job.events[job.events.length - 1];
  const detail = latest ? certificateConsoleEventText(latest) : "Waiting for the first progress event.";
  if (job.status === "queued") {
    return `Certificate job queued. ${detail}`;
  }
  if (job.status === "running") {
    return `Certificate job running. ${detail}`;
  }
  if (job.status === "succeeded") {
    return `Certificate job succeeded. ${detail}`;
  }
  return `Certificate job ${job.status}. ${detail}`;
}

function operationValue(value: string | null | undefined, fallback: string): string {
  const normalized = (value ?? "").trim();
  if (!normalized || ["not assigned", "unknown"].includes(normalized.toLowerCase())) {
    return fallback;
  }
  return normalized;
}

function outboundProfileLabel(profileName: string | null | undefined, chainId: string): string {
  return operationValue(profileName, chainId).replace(/-edge-(\d+)$/, "-$1");
}

function coreHostCountLabel(operations: EngagementOperationsOverview | null): string {
  if (!operations) {
    return "0";
  }
  const total = operations.healthSummary.hostCount ?? operations.coreInfrastructure.length;
  const active = operations.healthSummary.activeHostCount ?? total;
  if (total > 0 && active !== total) {
    return `${active} active / ${total} last-known`;
  }
  return String(total);
}

function inboundRelayPortLabel(channel: Pick<InboundChannelInput, "relayPort" | "middleRelayPort" | "proxyRelayPort" | "externalPort" | "protocol" | "mode">): string {
  const protocol = (channel.protocol ?? "").toUpperCase();
  const mode = channel.mode ?? "";
  const middle = operationValue(channel.middleRelayPort ?? channel.relayPort, "");
  const proxy = operationValue(channel.proxyRelayPort ?? channel.relayPort, "");
  if (protocol !== "UDP" && mode !== "udp-forward") {
    return operationValue(channel.externalPort, "N/A");
  }
  if (middle && proxy && middle !== proxy) {
    return `middle ${middle}, proxy ${proxy}`;
  }
  return middle || proxy || operationValue(channel.externalPort, "N/A");
}

function inboundRouteLabel(channel: Pick<InboundChannelInput, "edge" | "externalPort" | "middle" | "proxy" | "terminatesOn" | "internalPort" | "relayPort" | "middleRelayPort" | "proxyRelayPort" | "protocol" | "mode">): string {
  const protocol = operationValue(channel.protocol, "TCP");
  const external = operationValue(channel.externalPort, "N/A");
  const middleRelay = operationValue(channel.middleRelayPort ?? channel.relayPort, external);
  const proxyRelay = operationValue(channel.proxyRelayPort ?? channel.relayPort, middleRelay);
  const termination = operationValue(channel.internalPort, "N/A");
  if (protocol.toUpperCase() === "UDP" || channel.mode === "udp-forward") {
    return `${operationValue(channel.edge, "edge")}:${external}/udp -> ${operationValue(channel.middle, "middle")}:${middleRelay}/udp -> ${operationValue(channel.proxy, "proxy")}:${proxyRelay}/udp -> ${operationValue(channel.terminatesOn, "termination")}:${termination}/udp`;
  }
  return `${operationValue(channel.edge, "edge")}:${external} to ${operationValue(channel.terminatesOn, "termination")}:${termination}`;
}

function inboundHostOptionsFromOperations(
  operations: EngagementOperationsOverview | null,
  _draft: InboundChannelFormState,
  engagementName: string
): InboundHostOptions {
  if (!operations) {
    return { proxies: [], middles: [], edges: [], terminations: [] };
  }
  const coreHosts = operations.coreInfrastructure ?? [];
  const sketchHosts = (operations.sketchInfrastructure ?? []).filter((host) => {
    const status = operationValue(host.status, "").toLowerCase();
    return !host.burned && status === "deployed";
  });
  const proxyHostnames = coreHosts
    .filter((host) => host.role.toLowerCase().startsWith("proxy") || host.hostname.toLowerCase().startsWith("proxy"))
    .map((host) => host.hostname);
  const middleHostnames = sketchHosts
    .filter((host) => host.role === "middle")
    .map((host) => host.hostname);
  const edges = sketchHosts.filter((host) => host.role === "edge" && host.chainId.trim() && host.componentId?.trim());
  const identityCounts = new Map<string, number>();
  edges.forEach((edge) => {
    const identity = inboundEdgeOptionValue(edge.chainId, edge.componentId ?? "");
    identityCounts.set(identity, (identityCounts.get(identity) ?? 0) + 1);
  });
  const hostnameCounts = new Map<string, number>();
  edges.forEach((edge) => hostnameCounts.set(edge.hostname, (hostnameCounts.get(edge.hostname) ?? 0) + 1));
  const edgeOptions = edges
    .filter((edge) => identityCounts.get(inboundEdgeOptionValue(edge.chainId, edge.componentId ?? "")) === 1)
    .map((edge) => ({
      edge,
      attachment: inboundEdgeAttachment(operations, edge.chainId, edge.componentId ?? "", edge.hostname, engagementName)
    }))
    .filter((candidate): candidate is { edge: typeof edges[number]; attachment: NonNullable<ReturnType<typeof inboundEdgeAttachment>> } => candidate.attachment !== null)
    .map(({ edge, attachment }) => {
      const provider = operationValue(edge.provider, "provider unknown");
      const region = operationValue(edge.region, "region unknown");
      const route = `via ${edge.assignedProxyId} (${attachment.proxyHostname})`;
      const address = operationValue(edge.publicIp, "IP not recorded");
      const detail = `${provider}/${region}, ${route}, ${address}`;
      return {
        value: inboundEdgeOptionValue(edge.chainId, edge.componentId ?? ""),
        label: hostnameCounts.get(edge.hostname) === 1 ? edge.hostname : `${edge.hostname} — ${detail}`,
        chainId: edge.chainId,
        componentId: edge.componentId ?? "",
        hostname: edge.hostname,
      };
    });
  const terminationHostnames = coreHosts.map((host) => host.hostname);
  return {
    proxies: hostOptions(proxyHostnames),
    middles: hostOptions(middleHostnames),
    edges: edgeOptions,
    terminations: hostOptions(terminationHostnames)
  };
}

function inboundEdgeOptionValue(chainId: string, componentId: string): string {
  return JSON.stringify([chainId.trim(), componentId.trim()]);
}

const standardTcpPublicIngressPorts = ["80", "443", "2222"];
const backflipsPort = "2222";

function inboundBackflipsProxySocketWarning(
  channel: InboundChannelFormState,
  attachment: ReturnType<typeof inboundEdgeAttachment>
): string {
  const protocol = operationValue(channel.protocol, "TCP").toUpperCase();
  if (protocol === "UDP" || channel.mode === "udp-forward") {
    return "";
  }
  const proxyHostname = attachment?.proxyHostname ?? "";
  if (!proxyHostname || channel.terminatesOn !== proxyHostname) {
    return "";
  }
  const proxyRelayPort = operationValue(channel.proxyRelayPort || channel.relayPort || channel.externalPort, "");
  const internalPort = operationValue(channel.internalPort, "");
  if (proxyRelayPort !== backflipsPort || internalPort !== backflipsPort) {
    return "";
  }
  const backflipsLikeText = `${channel.service} ${channel.purpose} ${channel.channelId}`.toLowerCase();
  if (!backflipsLikeText.includes("backflip") && channel.externalPort !== backflipsPort) {
    return "";
  }
  return `SSH Backflips owns ${proxyHostname}:${backflipsPort}. Use the SSH Backflips capability configuration, or choose a separate proxy relay port for a generic TCP route.`;
}

function inboundPublicIngressPolicy(
  operations: EngagementOperationsOverview | null,
  channel: Pick<InboundChannelFormState, "chainId" | "edge" | "edgeComponentId" | "externalPort" | "protocol">
): InboundPublicIngressPolicy {
  const selectedEdge = inboundSelectedEdge(operations, channel.chainId, channel.edgeComponentId, channel.edge);
  const standardPorts = standardTcpPublicIngressPorts.join(", ");
  const protocol = operationValue(channel.protocol, "TCP").toUpperCase();
  const normalizedProtocol = protocol === "UDP" ? "UDP" : "TCP";
  const selectedPort = operationValue(channel.externalPort, "");

  if (!selectedEdge) {
    return {
      edgeLabel: "Select edge",
      detail: "Select a deployed edge before recording an inbound channel so Barragan can show the provider and public ingress expectations for that route.",
      level: "empty",
      providerLabel: "N/A",
      standardPorts,
      status: "Select Edge",
      title: "Select an edge to see public ingress expectations."
    };
  }

  const provider = operationValue(selectedEdge.provider, "provider unknown");
  const region = operationValue(selectedEdge.region, "region unknown");
  const publicIp = operationValue(selectedEdge.publicIp, "public IP not recorded");
  const edgeLabel = `${selectedEdge.hostname} (${publicIp})`;
  const providerLabel = `${provider} / ${region}`;

  if (normalizedProtocol === "UDP") {
    return {
      edgeLabel,
      detail: `Barragan will sync public UDP/${selectedPort || "port"} ingress on the selected ${provider} edge and allocate protected middle/proxy relay ports. Inspector should verify public ingress after apply.`,
      level: "udp",
      providerLabel,
      standardPorts,
      status: "Managed On Apply",
      title: "Barragan manages this UDP route from its public edge inward."
    };
  }

  if (selectedPort && standardTcpPublicIngressPorts.includes(selectedPort)) {
    return {
      edgeLabel,
      detail: `TCP/${selectedPort} is in Barragan's standard public ingress set for sketch edges. Route validation still proves the edge-local path only; public internet ingress should be checked after apply.`,
      level: "standard",
      providerLabel,
      standardPorts,
      status: "Standard Port",
      title: `TCP/${selectedPort} matches the standard public ingress policy.`
    };
  }

  return {
    edgeLabel,
    detail: `TCP/${selectedPort || "port"} is outside Barragan's standard public ingress ports. Edge-local route validation can pass while public internet ingress is still blocked by provider firewall policy.`,
    level: "advanced",
    providerLabel,
    standardPorts,
    status: "Advanced Port",
    title: selectedPort ? `TCP/${selectedPort} needs explicit public ingress verification.` : "Enter an external TCP port to assess the public ingress policy."
  };
}

function inboundSelectedEdge(
  operations: EngagementOperationsOverview | null,
  chainId: string,
  componentId: string,
  edgeHostname = ""
): EngagementOperationsOverview["sketchInfrastructure"][number] | null {
  const expectedChain = chainId.trim();
  const expectedComponent = componentId.trim();
  const expectedHostname = edgeHostname.trim();
  if (!operations || !expectedChain || !expectedComponent) {
    return null;
  }
  const matches = (operations.sketchInfrastructure ?? []).filter((host) => {
    const status = operationValue(host.status, "").toLowerCase();
    return host.role === "edge" && host.chainId === expectedChain && host.componentId === expectedComponent &&
      (!expectedHostname || host.hostname === expectedHostname) && !host.burned && status === "deployed";
  });
  return matches.length === 1 ? matches[0] : null;
}

function inboundEdgeAttachment(
  operations: EngagementOperationsOverview | null,
  chainId: string,
  componentId: string,
  edgeHostname = "",
  _engagementName = ""
): { edgeHostname: string; middleHostname: string; middleComponentId: string; proxyHostname: string; proxyLabel: string; homebaseHostname: string } | null {
  const edge = inboundSelectedEdge(operations, chainId, componentId, edgeHostname);
  if (!operations || !edge?.chainId) {
    return null;
  }
  const edgeProxy = edge.assignedProxyId ?? "";
  if (!/^proxy[0-9]+$/.test(edgeProxy) || edge.proxy !== edgeProxy) {
    return null;
  }
  const middles = operations.sketchInfrastructure.filter((host) =>
    host.role === "middle" && host.chainId === edge.chainId && host.componentId?.trim() &&
    !host.burned && operationValue(host.status, "").toLowerCase() === "deployed" &&
    host.assignedProxyId === edgeProxy && host.proxy === edgeProxy
  );
  const middle = middles.length === 1 ? middles[0] : null;
  const proxy = coreHostBySemanticId(operations, edgeProxy);
  const homebase = coreHostBySemanticId(operations, "homebase");
  if (!middle || !proxy || !homebase) {
    return null;
  }
  return {
    edgeHostname: edge.hostname,
    middleHostname: middle.hostname,
    middleComponentId: middle.componentId ?? "",
    proxyHostname: proxy.hostname,
    proxyLabel: shortHostName(proxy.hostname),
    homebaseHostname: homebase.hostname
  };
}

function operatorChannelStatus(value: string | null | undefined): string {
  const normalized = operationValue(value, "Not Ready").toLowerCase();
  if (normalized === "validated") {
    return "Ready";
  }
  if (normalized === "removed") {
    return "Removed";
  }
  if (normalized.includes("failed")) {
    return operationValue(value, "Failed");
  }
  if (normalized.includes("pending validation")) {
    return "Needs Validation";
  }
  if (normalized.includes("pending") || normalized.includes("config")) {
    return "Configuring";
  }
  return operationValue(value, "Not Ready");
}

function retryAttemptBoundaryIndex(events: JobEvent[]): number {
  let boundary = -1;
  events.forEach((event, index) => {
    const message = stringValue(event.message).toLowerCase();
    const data = recordValue(event.data);
    const explicitRetryStart = /\bretry (queued|started)\b/.test(message) ||
      stringValue(data.bootstrap).toLowerCase() === "retrying";
    if (explicitRetryStart) {
      boundary = index;
    }
  });
  return boundary;
}

function currentJobAttemptEvents(job: JobRunDetail | null): JobEvent[] {
  const events = job?.events ?? [];
  const boundary = retryAttemptBoundaryIndex(events);
  return boundary > 0 ? events.slice(boundary) : events;
}

function priorJobAttemptEvents(job: JobRunDetail | null): JobEvent[] {
  const events = job?.events ?? [];
  const boundary = retryAttemptBoundaryIndex(events);
  return boundary > 0 ? events.slice(0, boundary) : [];
}

function terminalSummaryLooksActive(value: string): boolean {
  return /\b(waiting|queued|running|starting|applying|preparing|working|failing|in progress)\b/i.test(value);
}

function terminalSummaryLooksSuccessful(value: string): boolean {
  return /\b(succeeded|completed|applied|configured|validated|removed|issued|renewed|ready)\b/i.test(value);
}

export function progressConsolePrimaryState(
  job: JobRunDetail | null,
  summary: string,
  activeTask = ""
): ProgressConsolePrimaryState {
  if (!job) {
    return { label: "Status", text: summary || "No job activity is available yet." };
  }
  if (job.status === "succeeded") {
    return {
      label: "Outcome",
      text: summary &&
        !/\bfail(ed|ure|ing)?\b/i.test(summary) &&
        (!terminalSummaryLooksActive(summary) || terminalSummaryLooksSuccessful(summary))
        ? summary
        : "Completed successfully."
    };
  }
  if (job.status === "failed") {
    const latestFailure = [...currentJobAttemptEvents(job)].reverse().find((event) => event.level === "error");
    const safeSummary = summary &&
      /\b(failed|failure|error|needs attention)\b/i.test(summary) &&
      !terminalSummaryLooksSuccessful(summary)
      ? summary
      : "";
    return {
      label: "Current failure",
      text: safeSummary || stringValue(latestFailure?.message) || "Job failed. Review the current attempt log before retrying."
    };
  }
  if (job.status === "queued") {
    return { label: "Status", text: summary || "Job is queued." };
  }
  return {
    label: "Current task",
    text: activeTask || summary || stringValue(currentJobAttemptEvents(job).at(-1)?.message) || "Waiting for job activity"
  };
}

function ProgressConsolePrimaryLine({
  job,
  summary,
  activeTask = ""
}: {
  job: JobRunDetail | null;
  summary: string;
  activeTask?: string;
}) {
  const primary = progressConsolePrimaryState(job, summary, activeTask);
  return <p><strong>{primary.label}:</strong> {primary.text}</p>;
}

export function jobConsoleText(
  job: JobRunDetail | null,
  emptyText: string,
  formatEvent: (event: JobEvent) => string = (event) => stringValue(event.message) || "Job event."
): string {
  if (!job) {
    return emptyText;
  }
  const eventLines = (events: JobEvent[]) => events.map((event) => {
    const level = event.level ? event.level.toUpperCase() : "INFO";
    return `${event.sequence}. ${level} ${formatEvent(event)}`;
  });
  const currentLines = eventLines(currentJobAttemptEvents(job));
  const priorLines = eventLines(priorJobAttemptEvents(job));
  const attemptBlock = priorLines.length
    ? [
        "current attempt",
        currentLines.length ? currentLines.join("\n") : "No current-attempt events recorded.",
        "",
        "prior attempt history",
        priorLines.join("\n")
      ].join("\n")
    : currentLines.length ? currentLines.join("\n") : "No events recorded.";
  return [
    `job ${job.id}`,
    `action ${job.action}`,
    `status ${job.status}`,
    "",
    attemptBlock
  ].join("\n");
}

function infrastructureConsoleText(
  job: JobRunDetail | null,
  emptyText: string,
  steps: Array<DeploymentStep & { statusLabel: string }>
): string {
  const progressLines = steps.map((step, index) => {
    const active = step.active ? " active" : "";
    return `${index + 1}. ${step.statusLabel}${active} ${step.label}`;
  });
  const progressBlock = progressLines.length ? ["progress", ...progressLines].join("\n") : "";
  const jobBlock = jobConsoleText(job, emptyText, infrastructureConsoleEventText);
  return progressBlock ? `${progressBlock}\n\n${jobBlock}` : jobBlock;
}

function infrastructureJobProgressMessage(
  job: JobRunDetail,
  teardown: boolean,
  activeStep: (DeploymentStep & { statusLabel: string }) | null
): string {
  if (job.status === "queued") {
    return teardown ? "Infrastructure teardown is queued." : "Infrastructure deployment is queued.";
  }
  if (job.status === "running") {
    if (activeStep) {
      return `${activeStep.label} is ${activeStep.status === "failed" ? "failing" : "running"}.`;
    }
    return teardown ? "Infrastructure teardown is running." : "Infrastructure deployment is running.";
  }
  if (job.status === "succeeded") {
    if (teardown) {
      return "Infrastructure teardown succeeded.";
    }
    return job.input.postCoreSketchContinuationEligible === true
      ? "Core infrastructure is ready. Track post-core sketch rollout in Live sketch chain lifecycle."
      : "Infrastructure is ready and retained for engagement operations.";
  }
  if (activeStep?.status === "failed") {
    return `${activeStep.label} failed.`;
  }
  return teardown ? "Infrastructure teardown failed." : "Infrastructure deployment failed.";
}

export function infrastructureConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const status = stringValue(data.status);
  const commandResult = recordValue(data.commandResult);
  const commandStatus = stringValue(commandResult.returncode);
  const suffix = commandStatus ? ` (rc ${commandStatus})` : status ? ` (${status})` : "";
  const elapsed = Number(data.elapsedSeconds);
  const duration = Number.isFinite(elapsed) && elapsed >= 0 ? ` in ${formatActivityDuration(Math.round(elapsed))}` : "";

  if (message === "infrastructure command started") {
    return `${stringValue(data.phase) || "Infrastructure command"} started.`;
  }
  if (message === "infrastructure command heartbeat") {
    return `${stringValue(data.phase) || "Infrastructure command"} is still working (${Number(data.elapsedSeconds) || 0}s elapsed).`;
  }
  if (message === "Ansible task progress") {
    const task = stringValue(data.task);
    const play = stringValue(data.play);
    return task ? `Ansible task: ${task}.` : play ? `Ansible play: ${play}.` : "Ansible is progressing.";
  }

  if (message === "OCI read preflight completed") {
    return `OCI read preflight completed${suffix}.`;
  }
  if (message === "Terraform init completed") {
    return `Terraform workspace initialized${duration}${suffix}.`;
  }
  if (message === "Terraform apply completed") {
    return event.level === "error"
      ? `Terraform failed to create core OCI infrastructure${duration}${suffix}.`
      : `Terraform created the core OCI infrastructure${duration}${suffix}.`;
  }
  if (message === "SSH readiness validation completed") {
    return `SSH readiness check completed${duration}${suffix}.`;
  }
  if (message === "Ansible ping validation completed") {
    return `Ansible ping validated core host access${duration}${suffix}.`;
  }
  if (message === "Ansible bootstrap validation completed") {
    return `Ansible configured the base RTI layout${duration}${suffix}.`;
  }
  if (message === "Ansible selected capabilities apply completed") {
    return `Ansible applied the selected RTI capabilities${duration}${suffix}.`;
  }
  if (message === "operator inspection ready") {
    return "Core infrastructure is ready and retained for engagement operations.";
  }
  if (message === "core infrastructure deployed; preparing continuous Inspector") {
    return "Core infrastructure deployed; preparing the retained Inspector for external validation.";
  }
  if (message === "continuous Inspector readiness started") {
    return "Preparing the retained Inspector for external validation.";
  }
  if (message === "continuous Inspector readiness succeeded") {
    return "The retained Inspector is ready for external validation.";
  }
  if (message === "continuous Inspector readiness failed; deployed core is retained") {
    return "The retained Inspector was not ready; core infrastructure remains available for recovery.";
  }
  if (message === "operator teardown requested") {
    return "Operator requested guarded infrastructure teardown.";
  }
  if (message === "Terraform destroy completed") {
    return `Terraform destroyed the core infrastructure${duration}${suffix}.`;
  }
  if (message === "cleanup verification completed") {
    return `Cleanup verification completed${suffix}.`;
  }
  if (message === "pilot Standard RTI teardown finished") {
    return "Pilot Standard RTI teardown finished.";
  }
  return message || "Infrastructure job event.";
}

export function sketchConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const elapsed = Number(data.elapsedSeconds);
  const duration = Number.isFinite(elapsed) && elapsed >= 0 ? ` in ${formatActivityDuration(Math.round(elapsed))}` : "";

  if (message === "terraform apply started") {
    return "Terraform sketch provisioning started.";
  }
  if (message === "terraform apply completed") {
    return `Terraform provisioned the sketch infrastructure${duration}.`;
  }
  if (message === "terraform apply failed") {
    return `Terraform sketch provisioning failed${duration}.`;
  }
  return message || "Sketch job event.";
}

export function sketchLifecycleConsoleCopy(job: JobRunDetail | null): { title: string; emptyText: string } {
  if (!job) {
    return { title: "Sketch deployment progress", emptyText: "Starting sketch infrastructure work." };
  }
  if (job.action === "sketch_edge_retire" || job.input.edgeTransition === "retire") {
    return { title: "Sketch edge retirement progress", emptyText: "Starting retained-middle edge retirement." };
  }
  if (job.action === "sketch_edge_replace" || job.input.edgeTransition === "replace") {
    return { title: "Sketch edge replacement progress", emptyText: "Starting retained-middle edge replacement." };
  }
  if (job.action.endsWith("_teardown")) {
    return { title: "Sketch teardown progress", emptyText: "Starting sketch infrastructure teardown." };
  }
  if (job.action.endsWith("_deploy")) {
    return { title: "Sketch deployment progress", emptyText: "Starting sketch infrastructure deployment." };
  }
  return { title: "Sketch lifecycle progress", emptyText: "Starting sketch infrastructure work." };
}

function channelConsoleText(job: JobRunDetail | null): string {
  return jobConsoleText(job, "No channel job events are available yet.", channelConsoleEventText);
}

function desktopConsoleText(job: JobRunDetail | null, emptyText: string): string {
  return jobConsoleText(job, emptyText, desktopConsoleEventText);
}

function opsecConsoleText(job: JobRunDetail | null, emptyText: string): string {
  return jobConsoleText(job, emptyText, opsecConsoleEventText);
}

function defaultOpsecConfiguration(): OpsecNetworkRestrictionsConfiguration {
  return {
    enabled: false,
    destinations: [],
    notes: "",
    purpose: "",
    managedComment: "barragan-opsec-network-restrictions"
  };
}

function opsecConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const commandResult = recordValue(data.commandResult);
  const commandStatus = stringValue(commandResult.returncode);
  const stdout = stringValue(commandResult.stdout).trim();
  const stderr = stringValue(commandResult.stderr).trim();
  const suffix = commandStatus ? ` (rc ${commandStatus})` : "";

  if (message === "OPSEC network restrictions workspace rendered") {
    return "Prepared OPSEC network restrictions workspace for homebase.";
  }
  if (message === "OPSEC network restrictions Ansible apply started") {
    return "Started OPSEC Ansible apply on homebase.";
  }
  if (message === "OPSEC network restrictions Ansible apply succeeded") {
    return `OPSEC Ansible apply succeeded${suffix}.${stdout ? `\nstdout:\n${stdout}` : ""}`;
  }
  if (message === "OPSEC network restrictions Ansible apply failed") {
    const details = [stderr ? `stderr:\n${stderr}` : "", stdout ? `stdout:\n${stdout}` : ""].filter(Boolean).join("\n\n");
    return `OPSEC Ansible apply failed${suffix}.${details ? `\n${details}` : ""}`;
  }
  return message || "OPSEC job event.";
}

function opsecJobProgressMessage(job: JobRunDetail): string {
  if (job.status === "queued") {
    return "OPSEC network restrictions apply is queued.";
  }
  if (job.status === "running") {
    const latest = job.events[job.events.length - 1];
    return latest ? opsecConsoleEventText(latest) : "OPSEC network restrictions apply is running.";
  }
  if (job.status === "succeeded") {
    return "OPSEC network restrictions apply succeeded.";
  }
  return "OPSEC network restrictions apply failed.";
}

function desktopConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const commandResult = recordValue(data.commandResult);
  const commandStatus = stringValue(commandResult.returncode);
  const stdout = stringValue(commandResult.stdout).trim();
  const stderr = stringValue(commandResult.stderr).trim();
  const suffix = commandStatus ? ` (rc ${commandStatus})` : "";

  if (message === "Desktop service apply workspace rendered") {
    return "Prepared Desktop service workspace for homebase.";
  }
  if (message === "Desktop service Ansible apply started") {
    return "Started Desktop Ansible apply on homebase.";
  }
  if (message === "Desktop service Ansible task started") {
    const taskName = stringValue(data.taskName);
    return taskName ? `Started Ansible task: ${taskName}.` : "Started Ansible task.";
  }
  if (message === "Desktop service Ansible task completed") {
    const taskName = stringValue(data.taskName);
    const result = stringValue(data.result);
    return taskName ? `Completed Ansible task: ${taskName}${result ? ` (${result})` : ""}.` : "Completed Ansible task.";
  }
  if (message === "Desktop service Ansible task failed") {
    const taskName = stringValue(data.taskName);
    const line = stringValue(data.line);
    return taskName ? `Failed Ansible task: ${taskName}.${line ? `\n${line}` : ""}` : "Failed Ansible task.";
  }
  if (message === "Desktop service Ansible apply succeeded") {
    return `Desktop Ansible apply succeeded${suffix}.${stdout ? `\nstdout:\n${stdout}` : ""}`;
  }
  if (message === "Desktop service Ansible apply failed") {
    const details = [stderr ? `stderr:\n${stderr}` : "", stdout ? `stdout:\n${stdout}` : ""].filter(Boolean).join("\n\n");
    return `Desktop Ansible apply failed${suffix}.${details ? `\n${details}` : ""}`;
  }
  return message || "Desktop service job event.";
}

function desktopJobProgressMessage(job: JobRunDetail): string {
  if (job.status === "queued") {
    return "Desktop service apply is queued.";
  }
  if (job.status === "running") {
    const latest = job.events[job.events.length - 1];
    return latest ? desktopConsoleEventText(latest) : "Desktop service apply is running.";
  }
  if (job.status === "succeeded") {
    return "Desktop service apply succeeded.";
  }
  return "Desktop service apply failed.";
}

function backflipsConsoleEventText(event: JobEvent): string {
  const message = event.message || "";
  const data = event.data ?? {};
  const stdout = stringValue((data.commandResult as Record<string, unknown> | undefined)?.stdout);
  const stderr = stringValue((data.commandResult as Record<string, unknown> | undefined)?.stderr);
  const rc = stringValue((data.commandResult as Record<string, unknown> | undefined)?.returncode);
  const suffix = rc ? ` (rc ${rc})` : "";
  if (message === "backflips service apply workspace rendered") {
    return "Prepared Backflips bootstrap workspace.";
  }
  if (message === "backflips service Ansible apply started") {
    return "Started Backflips bootstrap Ansible apply.";
  }
  if (message === "backflips service Ansible apply succeeded") {
    return `Backflips bootstrap succeeded${suffix}.${stdout ? `\nstdout:\n${stdout}` : ""}`;
  }
  if (message === "backflips service Ansible apply failed") {
    const details = [stderr ? `stderr:\n${stderr}` : "", stdout ? `stdout:\n${stdout}` : ""].filter(Boolean).join("\n\n");
    return `Backflips bootstrap failed${suffix}.${details ? `\n${details}` : ""}`;
  }
  return message || "Backflips job event.";
}

function teamAccessJobProgressMessage(job: JobRunDetail): string {
  if (job.status === "queued") {
    return "Core-host access apply is queued.";
  }
  if (job.status === "running") {
    const latest = job.events[job.events.length - 1];
    return latest ? teamAccessConsoleEventText(latest) : "Core-host access apply is running.";
  }
  if (job.status === "succeeded") {
    return "Core-host access apply succeeded.";
  }
  return "Core-host access apply failed.";
}

function teamAccessConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const targets = arrayValue(data.targetHosts).map((target) => stringValue(target)).filter(Boolean);
  const commandResult = recordValue(data.commandResult);
  const commandStatus = stringValue(commandResult.returncode);
  const enabledUsers = arrayValue(data.enabledUsers).map((user) => stringValue(user)).filter(Boolean);
  const disabledUsers = arrayValue(data.disabledUsers).map((user) => stringValue(user)).filter(Boolean);

  if (message === "core access workspace rendered") {
    return "Prepared core-host access workspace.";
  }
  if (message === "core host targets selected") {
    return targets.length ? `Selected core targets: ${targets.join(", ")}.` : "Selected core host targets.";
  }
  if (message === "sketch targets omitted for OPSEC") {
    return "Confirmed named operator accounts will not be pushed to sketch middle or edge nodes.";
  }
  if (message === "core access Ansible apply started") {
    const enableUsers = arrayValue(data.enableUsers).map((user) => stringValue(user)).filter(Boolean);
    const disableUsers = arrayValue(data.disableUsers).map((user) => stringValue(user)).filter(Boolean);
    const parts = [];
    if (enableUsers.length) {
      parts.push(`enable ${enableUsers.join(", ")}`);
    }
    if (disableUsers.length) {
      parts.push(`disable ${disableUsers.join(", ")}`);
    }
    return parts.length ? `Started Ansible core access apply to ${parts.join("; ")}.` : "Started Ansible core access apply.";
  }
  if (message === "core access Ansible apply succeeded") {
    const parts = [];
    if (enabledUsers.length) {
      parts.push(`enabled ${enabledUsers.join(", ")}`);
    }
    if (disabledUsers.length) {
      parts.push(`disabled ${disabledUsers.join(", ")}`);
    }
    return `Core-host access apply succeeded${parts.length ? `: ${parts.join("; ")}` : ""}${commandStatus ? ` (rc ${commandStatus})` : ""}.`;
  }
  if (message === "core access Ansible apply failed") {
    const error = stringValue(data.error);
    return error || `Core-host access apply failed${commandStatus ? ` (rc ${commandStatus})` : ""}.`;
  }
  return message || "Core access job event.";
}

function channelConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const channelId = stringValue(data.channelId);
  const phase = stringValue(data.phase);
  const phaseLabel = stringValue(data.phaseLabel);
  const targets = channelConsoleTargets(data);
  const targetText = targets.length ? ` on ${targets.join(", ")}` : "";
  const status = stringValue(data.status);
  const validationEvidence = recordValue(data.validationEvidence);
  const validationDetail = stringValue(validationEvidence.detail);
  const commandResult = recordValue(data.commandResult);
  const commandStatus = stringValue(commandResult.returncode);

  if (message === "inbound channel apply workspace rendered") {
    return `Prepared apply workspace${channelId ? ` for ${channelId}` : ""}${targetText}.`;
  }
  if (message === "inbound channel Ansible apply started") {
    const commands = arrayValue(data.commands)
      .map((command) => stringValue(recordValue(command).phaseLabel) || stringValue(recordValue(command).label))
      .filter(Boolean);
    return commands.length
      ? `Started apply workflow: ${commands.join(" -> ")}.`
      : "Started inbound apply workflow.";
  }
  if (message === "inbound channel apply phase started") {
    return `${phaseLabel || phase || "Apply phase"} started${targetText}.`;
  }
  if (message === "inbound channel apply phase succeeded") {
    return `${phaseLabel || phase || "Apply phase"} succeeded${targetText}${commandStatus ? ` (rc ${commandStatus})` : ""}.`;
  }
  if (message === "inbound channel apply phase failed") {
    return `${phaseLabel || phase || "Apply phase"} failed${targetText}${commandStatus ? ` (rc ${commandStatus})` : ""}.`;
  }
  if (message === "inbound channel Ansible apply succeeded") {
    return "Inbound route applied on proxy, middle, and edge; validation is next.";
  }
  if (message === "inbound channel validation pending") {
    return "Apply finished; validation is pending or queued.";
  }
  if (message === "inbound channel automatic validation failed to start") {
    const errors = arrayValue(data.errors).map((error) => stringValue(error)).filter(Boolean);
    return errors.length ? `Automatic validation did not start: ${errors.join("; ")}.` : "Automatic validation did not start.";
  }
  if (message === "inbound channel validation workspace rendered") {
    return `Prepared validation workspace${targetText}.`;
  }
  if (message === "inbound channel validation started") {
    return "Started edge-local validation probe through the inbound route.";
  }
  if (message === "inbound channel validation succeeded") {
    return validationDetail || "Inbound route validation succeeded.";
  }
  if (message === "inbound channel validation failed") {
    return validationDetail || "Inbound route validation failed.";
  }
  if (message === "inbound channel remove workspace rendered") {
    return `Prepared remove workspace${channelId ? ` for ${channelId}` : ""}.`;
  }
  if (message === "inbound channel Ansible remove started") {
    return "Started inbound route removal.";
  }
  if (message === "inbound channel Ansible remove succeeded") {
    return "Removed stream configs and firewall rules for this inbound channel.";
  }
  if (message === "inbound channel removed") {
    return "Inbound channel marked removed.";
  }
  if (status && status !== message) {
    return `${message} (${status}).`;
  }
  return message || "Channel job event.";
}

function certificateConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const channelId = stringValue(data.channelId);
  const certificate = recordValue(data.certificate);
  const certType = stringValue(certificate.type);
  const certStatus = stringValue(certificate.status);
  const command = arrayValue(data.command).map((part) => stringValue(part)).filter(Boolean);

  if (message === "inbound channel certificate issue rendered") {
    return `Prepared ${certType || "certificate"} issue workflow${channelId ? ` for ${channelId}` : ""}.`;
  }
  if (message === "inbound channel certificate renew rendered") {
    return `Prepared ${certType || "certificate"} renewal workflow${channelId ? ` for ${channelId}` : ""}.`;
  }
  if (message === "inbound channel certificate revoke rendered") {
    return `Prepared ${certType || "certificate"} revoke workflow${channelId ? ` for ${channelId}` : ""}.`;
  }
  if (message === "inbound channel certificate state recorded") {
    return `Recorded certificate state${certStatus ? `: ${certStatus}` : ""}.`;
  }
  if (message === "selected-proxy certificate issuance started") {
    return "Started Certbot on the selected proxy through homebase.";
  }
  if (message === "selected-proxy certificate issuance succeeded") {
    return "Certbot issued the certificate on the selected proxy.";
  }
  if (message === "selected-proxy certificate issuance failed") {
    return "Certbot failed on the selected proxy; review the safe command result below.";
  }
  if (message === "DNS-01 certificate workspace rendered") {
    return "Prepared proxy-held key, Barragan DNS-01, and certificate activation phases.";
  }
  if (message === "proxy private key retained and CSR prepared") {
    return "Generated the CSR while retaining the private key on the selected proxy.";
  }
  if (message === "DNS-01 ACME validation completed") {
    return "Namecheap DNS-01 validation and certificate issuance completed.";
  }
  if (message === "proxy certificate activation completed") {
    return "Activated the certificate in the selected proxy site container.";
  }
  if (message.startsWith("DNS-01 certificate ")) {
    return message;
  }
  if (command.length) {
    return `${message}: ${command.join(" ")}`;
  }
  return message || "Certificate job event.";
}

function channelConsoleTargets(data: Record<string, unknown>): string[] {
  const targets = arrayValue(data.inventoryTargets).map((target) => stringValue(target)).filter(Boolean);
  if (targets.length) {
    return targets;
  }
  const route = recordValue(data.resolvedRoute);
  return ["proxy", "middle", "edge", "termination"]
    .map((key) => stringValue(recordValue(route[key]).name))
    .filter(Boolean);
}

function hostOptions(values: string[]): HostOption[] {
  const seen = new Set<string>();
  return values
    .map((value) => value.trim())
    .filter((value) => {
      if (!value || seen.has(value)) {
        return false;
      }
      seen.add(value);
      return true;
    })
    .map((value) => ({ value, label: value }));
}

function withCurrentHostOption(options: HostOption[], value: string): HostOption[] {
  const current = value.trim();
  if (!current || options.some((option) => option.value === current)) {
    return options;
  }
  return [{ value: current, label: current }, ...options];
}

function shortHostName(value: string): string {
  return value.trim().split(".", 1)[0].toLowerCase();
}

function hostProxyMatches(candidate: string, selectedProxy: string, engagementName = ""): boolean {
  const engagement = engagementName.trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
  const semantic = selectedProxy.trim().toLowerCase();
  const aliases = new Set([semantic, `${semantic}-${engagement}`, `${semantic}.infra.redteam`, `${semantic}-${engagement}.infra.redteam`]);
  return Boolean(engagement && aliases.has(candidate.trim().toLowerCase()));
}

function operationListValue(values: string[] | null | undefined, fallback: string): string {
  const normalized = (values ?? [])
    .map((value) => operationValue(value, ""))
    .filter(Boolean);
  return normalized.length ? normalized.join(", ") : fallback;
}

function defaultCapabilityApplyState(): CapabilityApplyState {
  return {
    status: "unsaved",
    selectionFingerprint: "",
    renderedInputFingerprint: "",
    preparedAt: "",
    startedAt: "",
    finishedAt: "",
    parentJobId: "",
    errors: [],
    children: []
  };
}

function capabilityApplyStateOf(workspace: EngagementCapabilityWorkspace | null | undefined): CapabilityApplyState {
  return workspace?.applyState ?? defaultCapabilityApplyState();
}

function capabilityApplyStatusLabel(status: CapabilityApplyState["status"]): string {
  switch (status) {
    case "saved_ready":
      return "Ready to apply";
    case "applying":
      return "Applying";
    case "applied":
      return "Applied";
    case "blocked":
      return "Configuration required";
    case "partial":
      return "Partially applied";
    case "failed":
      return "Apply failed";
    default:
      return "Ready to configure";
  }
}

function capabilityApplyStateMessage(applyState: CapabilityApplyState): string {
  const detail = applyState.errors.filter(Boolean).join("; ");
  switch (applyState.status) {
    case "saved_ready":
      return "Capability changes are saved and ready to apply.";
    case "applying":
      return "Saved capability changes are applying to running infrastructure.";
    case "applied":
      return "Saved capability changes were applied to running infrastructure.";
    case "blocked":
      return `Configuration required before applying saved capability changes.${detail ? ` ${detail}` : ""}`;
    case "partial":
      return `Some saved capability changes did not apply.${detail ? ` ${detail}` : " Review the apply progress for details."}`;
    case "failed":
      return `Saved capability apply failed.${detail ? ` ${detail}` : " Review the apply progress and retry when ready."}`;
    default:
      return "Save capability changes to prepare them for apply.";
  }
}

function capabilityApplyChildLabel(kind: "optional_roles" | "desktop"): string {
  return kind === "optional_roles" ? "Optional roles" : "Desktop applications";
}

function capabilityApplyChildStatusLabel(status: CapabilityApplyState["children"][number]["status"]): string {
  switch (status) {
    case "not_required":
      return "Not required";
    case "succeeded":
      return "Applied";
    case "failed":
      return "Failed";
    case "blocked":
      return "Blocked";
    case "running":
      return "Applying";
    default:
      return "Waiting";
  }
}

function capabilityReconciliationMessage(status: string, job: JobRunDetail | null, errors: string[] = []): string {
  const normalized = (job?.status || status || "").toLowerCase();
  const latest = job?.events?.[job.events.length - 1];
  const latestText = latest ? capabilityReconciliationConsoleEventText(latest) : "";
  if (normalized === "not-deployed") {
    return "Core infrastructure is not running yet. Selected roles will be applied during core deployment.";
  }
  if (normalized === "not-applicable") {
    return "No selected executable optional roles are ready to apply.";
  }
  if (normalized === "ready") {
    return "Selected optional roles are ready to apply to running core hosts.";
  }
  if (normalized === "queued") {
    return `Optional-role reconciliation is queued.${latestText ? ` ${latestText}` : ""}`;
  }
  if (normalized === "running") {
    return `Optional-role reconciliation is running.${latestText ? ` ${latestText}` : ""}`;
  }
  if (normalized === "succeeded") {
    return `Selected optional roles were applied successfully.${latestText ? ` ${latestText}` : ""}`;
  }
  const detail = errors.filter(Boolean).join("; ") || latestText;
  return `Optional-role reconciliation failed.${detail ? ` ${detail}` : " Review the progress log and retry."}`;
}

function capabilityReconciliationTargetSummary(entries: EngagementCapabilityEntry[]): string {
  if (!entries.length) {
    return "None selected";
  }
  const hostClasses = [...new Set(entries.map((entry) => capabilityHostClassLabel(entry.hostClass)))];
  return hostClasses.join(", ");
}

function capabilityReconciliationConsoleEventText(event: JobEvent): string {
  const data = recordValue(event.data);
  const message = stringValue(event.message);
  const hostClass = stringValue(data.hostClass);
  const role = stringValue(data.role) || stringValue(data.roleName);
  const commandResult = recordValue(data.commandResult);
  const returnCode = stringValue(commandResult.returncode);
  const stderr = stringValue(commandResult.stderr).trim();
  if (message.includes("workspace rendered")) {
    return "Prepared the engagement-scoped optional-role Ansible workspace.";
  }
  if (message.includes("Ansible apply started")) {
    return `Started Ansible apply${hostClass ? ` for ${capabilityHostClassLabel(hostClass)}` : ""}${role ? ` (${role})` : ""}.`;
  }
  if (message.includes("Ansible apply succeeded")) {
    return `Optional-role Ansible apply succeeded${returnCode ? ` (rc ${returnCode})` : ""}.`;
  }
  if (message.includes("Ansible apply failed")) {
    return `Optional-role Ansible apply failed${returnCode ? ` (rc ${returnCode})` : ""}.${stderr ? `\nstderr:\n${stderr}` : ""}`;
  }
  return message || "Optional-role reconciliation event.";
}

function capabilitySelectionKey(row: CapabilitySelectionRef): string {
  return `${row.hostClass}::${row.id}`;
}

function toggleSelectionRow(rows: CapabilitySelectionRef[], row: CapabilitySelectionRef): CapabilitySelectionRef[] {
  const key = capabilitySelectionKey(row);
  if (rows.some((candidate) => capabilitySelectionKey(candidate) === key)) {
    return rows.filter((candidate) => capabilitySelectionKey(candidate) !== key);
  }
  return [...rows, row].sort((left, right) => capabilitySelectionKey(left).localeCompare(capabilitySelectionKey(right)));
}

function sameSelectionRows(left: CapabilitySelectionRef[], right: CapabilitySelectionRef[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  const leftKeys = left.map(capabilitySelectionKey).sort();
  const rightKeys = right.map(capabilitySelectionKey).sort();
  return leftKeys.every((key, index) => key === rightKeys[index]);
}

function capabilityEntrySelected(
  entry: EngagementCapabilityEntry,
  deselectedDefaults: CapabilitySelectionRef[],
  selectedOptionals: CapabilitySelectionRef[]
): boolean {
  const key = capabilitySelectionKey({ hostClass: entry.hostClass, id: entry.id });
  if (entry.classification === "essential") {
    return true;
  }
  if (entry.classification === "default") {
    return !deselectedDefaults.some((row) => capabilitySelectionKey(row) === key);
  }
  if (entry.classification === "optional") {
    return selectedOptionals.some((row) => capabilitySelectionKey(row) === key);
  }
  return Boolean(entry.selected);
}

function capabilityHostClassLabel(value: string): string {
  if (value === "elk") return "ELK";
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function capabilityHostClassCount(groups: Record<string, EngagementCapabilityEntry[]>): number {
  return Object.values(groups).reduce((total, entries) => total + entries.length, 0);
}

function capabilityHostClassEntries(groups: Record<string, EngagementCapabilityEntry[]>): EngagementCapabilityEntry[] {
  return ["essential", "default", "optional"].flatMap((classification) => groups[classification] ?? []);
}

function capabilityChoiceLabel(entry: EngagementCapabilityEntry, selected: boolean): string {
  if (entry.locked || entry.classification === "essential") {
    return "Required";
  }
  if (entry.classification === "default") {
    return selected ? "Selected by default" : "Default removed";
  }
  if (entry.classification === "optional") {
    return selected ? "Selected" : "Optional";
  }
  return selected ? "Selected" : "Available";
}

function statusClassName(value: string): string {
  const normalized = value.toLowerCase().replaceAll("_", " ");
  if (normalized.includes("warning") || normalized.includes("critical") || normalized.includes("degraded")) {
    return "attention";
  }
  if (
    normalized.includes("healthy") ||
    normalized.includes("validated") ||
    (normalized.includes("verified") && !normalized.includes("not verified")) ||
    normalized.includes("standard port") ||
    normalized.includes("done")
  ) {
    return "healthy";
  }
  if (normalized.includes("burned") || normalized.includes("failed") || normalized.includes("blocked")) {
    return "burned";
  }
  if (
    normalized.includes("planned") ||
    normalized.includes("unknown") ||
    normalized.includes("pending") ||
    normalized.includes("not ready") ||
    normalized.includes("not checked") ||
    normalized.includes("not run") ||
    normalized.includes("destroyed") ||
    normalized.includes("removed")
  ) {
    return "unknown";
  }
  return "attention";
}

function barraganApiErrorSummary(error: unknown, fallback: string): string {
  if (!(error instanceof BarraganApiError)) {
    return fallback;
  }
  const body = recordValue(error.body);
  const errors = arrayValue(body.errors).map((entry) => String(entry)).filter(Boolean);
  if (errors.length) {
    return errors.join(" ");
  }
  return error.message || fallback;
}

function formatOperationsTimestamp(value?: string | null): string {
  if (!value) {
    return "not probed";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}
