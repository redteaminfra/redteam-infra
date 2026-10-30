/* Copyright (c) 2026, Oracle and/or its affiliates. */
import type { DashboardInventory } from "../api/client";

const labels: Record<string, string> = {
  compute_instance: "Compute instances", vcn: "VCNs", subnet: "Subnets",
  internet_gateway: "Internet gateways", route_table: "Route tables", security_list: "Security lists",
  instance: "Instances", droplet: "Droplets", boot_volume: "Boot volumes", firewall: "Firewalls"
};
const readable = (value: string) => labels[value] ?? value.replaceAll("_", " ");
const timestamp = (value: string | null) => value ? new Date(value).toLocaleString() : "Not observed";

export function ProviderInventoryPanel({ dashboard }: { dashboard: DashboardInventory | null }) {
  const discovery = dashboard?.providerDiscovery;
  const resources = dashboard?.providerInventory ?? [];
  const complete = discovery?.status === "checked";
  return (
    <article className="wide-panel" aria-label="Current provider inventory">
      <div className="section-heading">
        <div>
          <h3>Current Provider Inventory</h3>
          <p>Read-only observations of candidate infrastructure. Coverage is limited to the resource types listed below; this is not a complete billing inventory.</p>
        </div>
        <strong>{readable(discovery?.status ?? "not_checked")}</strong>
      </div>
      <p>{discovery?.detail ?? "Use Refresh Provider Inventory to check current provider resources."}</p>
      {discovery?.cached ? <p>Cached observation · {timestamp(discovery.observedAt)} · {Math.floor(discovery.ageSeconds ?? 0)} seconds old</p> : null}
      <div className="provider-observation-grid">
        {discovery?.providers.map((provider) => (
          <section className="provider-observation" aria-label={`${provider.provider} inventory check`} key={provider.provider}>
            <div className="section-heading"><h4>{provider.provider}</h4><strong>{readable(provider.status)}</strong></div>
            <p>{provider.detail}</p>
            <p>Observed: {timestamp(provider.observedAt)}</p>
            <p>{["checked", "partial"].includes(provider.status) ? `${provider.resourceCount} candidate resources returned${provider.status === "partial" ? " · incomplete coverage" : ""}` : "Resource presence unknown"}</p>
            <p>Coverage: {provider.coverage.map(readable).join(", ")}</p>
          </section>
        ))}
      </div>
      {resources.length ? (
        <div className="provider-observation-grid" aria-label="Discovered provider resources">
          {resources.map((resource) => (
            <section className="provider-observation" key={`${resource.provider}-${resource.resourceType}-${resource.resourceId}`}>
              <h4>{resource.name || resource.resourceId}</h4>
              <dl>
                <div><dt>Provider / type</dt><dd>{resource.provider} / {readable(resource.resourceType)}</dd></div>
                <div><dt>State / region</dt><dd>{resource.lifecycleState} / {resource.region || "Not recorded"}</dd></div>
                <div><dt>Engagement</dt><dd>{resource.engagementName || resource.engagementId || "Unmatched"}</dd></div>
                <div><dt>Record match</dt><dd>{resource.classification === "observation_only" ? "Read-only observation — protected" : resource.classification === "recorded" ? "Matches deployment records" : resource.classification === "barragan_orphan" ? "Needs ownership and cleanup review" : "Unmanaged — protected"}</dd></div>
                <div><dt>Ownership tag</dt><dd>{resource.barraganOwned ? "Barragan marker present" : "No Barragan ownership marker"}</dd></div>
                <div><dt>Resource ID</dt><dd>{resource.resourceId}</dd></div>
                <div><dt>Observed</dt><dd>{timestamp(resource.observedAt)}</dd></div>
              </dl>
            </section>
          ))}
        </div>
      ) : <p>{complete ? "No candidate resources were returned within the checked coverage." : "No resource observations are available. An incomplete or unavailable check does not prove resources are absent."}</p>}
    </article>
  );
}
