/* Copyright (c) 2026, Oracle and/or its affiliates. */
import type { InferenceProxyConfiguration, InferenceProxyStatus } from "../api/client";

export const defaultInferenceProxyConfiguration = (): InferenceProxyConfiguration => ({
  region: "",
  compartmentId: "",
  port: 8787
});

export function InferenceProxySettings({ configuration, onChange, disabled, selected, onToggle, onSave, saving, changed, serviceStatus, statusLoading = false, statusError = "", onCheck }: {
  configuration: InferenceProxyConfiguration;
  onChange: (value: InferenceProxyConfiguration) => void;
  disabled: boolean;
  selected: boolean;
  onToggle: () => void;
  onSave: () => void;
  saving: boolean;
  changed: boolean;
  serviceStatus?: InferenceProxyStatus | null;
  statusLoading?: boolean;
  statusError?: string;
  onCheck?: () => void;
}) {
  const compartment = /^ocid1\.compartment\.[a-z0-9-]+\.[a-z0-9.-]+$/.test(configuration.compartmentId)
    ? configuration.compartmentId : "<model-compartment-ocid>";
  const policies = [
    "inspect generative-ai-model",
    "use generative-ai-chat",
    "use generative-ai-text-embedding",
    "use generative-ai-text-rerank"
  ].map((permission) => `Allow dynamic-group <dynamic-group-name> to ${permission} in compartment id ${compartment}`).join("\n");
  const valid = Boolean(/^[a-z][a-z0-9-]{1,62}$/.test(configuration.region) && compartment !== "<model-compartment-ocid>" && Number.isInteger(configuration.port) && configuration.port >= 1024 && configuration.port <= 65535);
  const instanceId = serviceStatus?.homebaseIdentity?.instanceId;
  const membershipInstance = instanceId && /^ocid1\.instance\.[a-z0-9-]+\.[a-z0-9.-]+$/.test(instanceId)
    ? instanceId : "<homebase-instance-ocid>";
  const statusConfiguration = serviceStatus?.configuration;
  const configurationMatches = Boolean(statusConfiguration && statusConfiguration.region === configuration.region &&
    statusConfiguration.compartmentId === configuration.compartmentId && statusConfiguration.port === configuration.port);
  const observation = !changed && selected && configurationMatches && !statusLoading ? serviceStatus?.observation : null;
  const checking = serviceStatus?.status === "checking";
  const discoveryLabel: Record<string, string> = {
    discovering: "Discovery pending",
    catalog_available: "Model catalog available",
    no_eligible_models: "No eligible models",
    discovery_unavailable: "Discovery unavailable"
  };
  const errorLabel: Record<string, string> = {
    oci_authorization_required: "OCI authorization is required. Ask your OCI administrator to review the policies below.",
    oci_not_authorized_or_not_found: "OCI reported not authorized or not found. Check permissions, region and model compartment.",
    oci_discovery_timeout: "OCI discovery timed out. Check connectivity and try again after the next discovery retry.",
    oci_discovery_unavailable: "OCI discovery is unavailable. Check the Homebase service and upstream provider status."
  };
  return <>
    <p>Install a local inference gateway on Homebase. Applications on that host use authenticated requests to <code>http://127.0.0.1:{configuration.port || 8787}/v1</code>. No public channel is created.</p>
    <div className="service-form-grid">
      <label>
        <span>OCI inference region</span>
        <input aria-label="OCI inference region" value={configuration.region} placeholder="us-chicago-1" disabled={disabled}
          onChange={(event) => onChange({ ...configuration, region: event.target.value })} />
        <small>Choose a region that offers your models. It can differ from Homebase's region.</small>
      </label>
      <label>
        <span>Loopback port</span>
        <input aria-label="Inference Proxy loopback port" type="number" min={1024} max={65535} value={configuration.port || ""} disabled={disabled}
          onChange={(event) => onChange({ ...configuration, port: Number(event.target.value) })} />
        <small>Default 8787. Reserve a different port for other local services.</small>
      </label>
      <label className="wide-field">
        <span>Model compartment OCID</span>
        <input aria-label="Model compartment OCID" value={configuration.compartmentId} placeholder="ocid1.compartment.…" disabled={disabled}
          onChange={(event) => onChange({ ...configuration, compartmentId: event.target.value })} />
        <small>The compartment authorized for inference; it need not be the compute compartment.</small>
      </label>
    </div>
    <details className="inference-proxy-guidance">
      <summary>Required OCI permissions — configure in OCI</summary>
      <p>An OCI administrator must create or select a dynamic group containing this Homebase instance. {membershipInstance === "<homebase-instance-ocid>" ? "Homebase identity is not yet verified here. Replace the instance placeholder using OCI, or check the installed service below." : "This rule uses the current Homebase identity from its latest service check."} Replace the dynamic group name and qualify it with its identity domain where required.</p>
      <p>Example membership rule for a single instance:</p>
      <pre className="inference-policy-text">{`instance.id = '${membershipInstance}'`}</pre>
      <p>Grant model discovery and the inference operations you need in the model compartment. Create the policy in that compartment or an ancestor with authority over it. These examples include chat, embedding and reranking; omit unused operations and apply your organization's approved model restrictions.</p>
      <pre className="inference-policy-text">{policies}</pre>
      <p>Barragan installs the service and never changes IAM policies or dynamic groups. You can install before completing OCI permissions. Allow time for OCI policy propagation before checking access.</p>
      <p><a href="https://docs.oracle.com/en-us/iaas/Content/generative-ai/iam-policies.htm" target="_blank" rel="noreferrer">OCI Generative AI policies</a>{" · "}<a href="https://docs.oracle.com/en-us/iaas/Content/Identity/dynamicgroups/Writing_Matching_Rules_to_Define_Dynamic_Groups.htm" target="_blank" rel="noreferrer">Dynamic-group matching rules</a></p>
    </details>
    <section aria-label="Inference Proxy service and discovery status">
      <h3>Service and OCI discovery</h3>
      <p>Check the installed service on Homebase. This does not issue agent keys, change IAM or run inference.</p>
      {changed ? <p>Save and Apply your capability changes before checking. Existing results describe the saved configuration.</p> : null}
      {!changed && statusConfiguration && !configurationMatches ? <p>Configuration changed elsewhere. Reload the page to load saved settings; copy any unsaved edits first.</p> : null}
      {statusLoading ? <p role="status">Loading service status...</p> : checking ? <p role="status">Checking the Homebase service and OCI discovery...</p> : null}
      {statusError ? <p role="alert">{statusError}</p> : null}
      {!statusLoading && !statusError && !changed && serviceStatus?.errors.map((error, index) => <p key={index}>{error}</p>)}
      {observation ? <>
        <p><strong>Local service:</strong> {observation.localReady ? "Ready" : "Not ready"}</p>
        <p><strong>OCI discovery:</strong> {discoveryLabel[observation.discoveryStatus] ?? "Not verified"}{observation.discoveryStatus === "catalog_available" ? ` (${observation.modelCount} models)` : ""}</p>
        {observation.errorCode ? <p>{errorLabel[observation.errorCode] ?? "The service could not verify OCI discovery. Check its protected Homebase logs."}</p> : null}
        <p>Checked: {observation.checkedAt}{observation.lastRefreshAt ? ` · Last successful catalog refresh: ${observation.lastRefreshAt}` : ""}</p>
      </> : !statusLoading && !checking && !changed ? <p>No current service check is available.</p> : null}
      <p><strong>Inference access:</strong> Not verified. A healthy service or available model catalog does not prove an inference request succeeds.</p>
      <button className="secondary-action" type="button" onClick={onCheck} disabled={disabled || changed || !selected || !configurationMatches || statusLoading || checking || !serviceStatus?.bindingFingerprint || !onCheck}>Check service and OCI discovery</button>
    </section>
    <p className="guardrail-hint">Installation progress appears in the capability Apply log. On Homebase, <code>/opt/inference-proxy/venv/bin/inference-proxy-admin status</code> shows local readiness and the latest OCI discovery result. OCI inference access is not verified by service installation or its health check. After configuring OCI, run <code>/opt/inference-proxy/venv/bin/inference-proxy-admin model refresh</code>; issue a scoped agent key there and test your chosen model. Keep keys out of shared logs. Model probes may incur charges.</p>
    <p>Deselecting this role does not uninstall it. Removal is manual; preserve <code>/etc/inference-proxy</code> and <code>/var/lib/inference-proxy</code> when repairing or upgrading.</p>
    <small>Save prepares the selected roles. Apply the saved changes from Capabilities to install on running infrastructure.</small>
    <div className="form-actions">
      <button className="secondary-action" disabled={disabled} onClick={onToggle} type="button">{selected ? "Deselect Inference Proxy" : "Select Inference Proxy"}</button>
      <button className="primary-action" disabled={disabled || !changed || (selected && !valid)} onClick={onSave} type="button">{saving ? "Saving..." : "Save capability changes"}</button>
    </div>
  </>;
}
