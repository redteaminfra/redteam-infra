# Legacy Ansible Role Carry-over Tracker

> Deprecated historical snapshot.
>
> Do not use this file as the current source of truth for Ansible role adoption
> or Barragan capability status. It fell out of date as capability manifests and
> work items became the operational tracker. Keep this file only as historical
> context for how the review started.
>
> Current sources of truth:
>
> - Adoption model: `spec/ansible-role-adoption.md`
> - Capability metadata: `barragan/capabilities/` in the active
>   `redteam-infra` manifest branch
> - Barragan work queue and decisions: `TODO.md`, `work-items/`, and
>   `decisions/`

This document tracks how legacy Ansible role behavior from the real
`redteam-infra` template repository maps into Barragan. It is intentionally a
product and engineering tracker, not a verbatim role inventory dump. Use it to
decide which roles should become Barragan-managed capabilities, which behavior
belongs in core provisioning, and which legacy material should remain
reference-only.

Last updated: 2026-07-23

| Legacy role | What it does | Carry-over status | Recommendation |
|---|---|---|---|
| `keepassxc` | Installs the KeePassXC desktop password manager package on homebase. | Done | Keep as part of the grouped `Desktop` Service. Current behavior should stay limited to package install unless a separate credential/vault workflow is designed. |
| `google-chrome` | Installs Google Chrome and managed Chrome policy files. | Done | Keep as a `Desktop` app toggle. Avoid adding browser profile or extension behavior unless explicitly scoped. |
| `firefox` | Removes Snap Firefox, configures Mozilla apt/PPA behavior, installs Firefox, and writes Firefox policy files. | Done | Keep as a `Desktop` app toggle. Current disable path removes package/policy files but intentionally does not restore Snap behavior. |
| `vs-code` | Installs Microsoft VS Code from the Microsoft apt repository. | Done | Keep as a `Desktop` app toggle. |
| `libreoffice` | Installs LibreOffice on demand. | Done | Keep as a `Desktop` app toggle. Deselecting removes only the upstream `libreoffice` meta-package, with purge and autoremove disabled; component packages may remain and the UI must say so. |
| `nmap` | Installs Nmap; legacy role compiled a specific upstream version when missing. | Done, but not as a Service | Keep as baseline operator tooling installed on homebase and proxy nodes during core provisioning. Do not expose as optional Desktop UI. |
| `homebase` | Configures legacy homebase workstation/server conveniences, skeleton files, helper scripts, proxy configuration material, and local RTI layout assumptions. | Partially carried over | Continue folding selected behavior into core provisioning only when it matches current Barragan architecture. `/engagement` ownership moved to the dedicated `engagement-workspace` role. Do not expose as a standalone Service. |
| `proxies` | Configures legacy proxy-node baseline behavior and depends on Nmap. | Partially carried over | Continue folding selected behavior into core provisioning. Do not expose as optional Service. |
| `nfs-server` | Configures NFS exports such as `/dropbox` from homebase. | Partially carried over | Already represented by Dropbox/homebase export work. Do not expose separately unless Dropbox becomes a first-class managed Service. |
| `nfs-client` | Configures NFS client mounts on hosts that consume homebase exports. | Partially carried over | Already represented by proxy Dropbox mount work. Keep in core provisioning. |
| `common` | Applies generic host conveniences such as shared config templates and editor defaults. | Partial / implicit | Carry over only specific, reviewed baseline behavior. Avoid broad import because it can introduce hidden host assumptions. |
| `unattended-upgrades` | Configures automatic package security updates. | Not carried over | Candidate for a future baseline hardening or platform maintenance feature. Needs explicit policy decision. |
| `molly-guard` | Installs safeguards to reduce accidental shutdown/reboot of remote systems. | Not carried over | Candidate for baseline safety/hardening if operators still want it. Low urgency. |
| `yama` | Configures Linux Yama ptrace hardening behavior. | Not carried over | Candidate for baseline hardening, but review against current kernel/security expectations before applying. |
| `opsec` | Applies network OPSEC controls such as blocking access to specified CIDRs. | Done | Keep as a configurable Homebase OPSEC capability. Barragan must validate CIDRs and only remove Barragan-managed firewall rules. |
| `oci` | Applies OCI-specific host/resolver behavior. | Not carried over as a role | Keep provider-specific behavior inside OCI provider/core provisioning paths. Do not expose as a Service. |
| `aws` | Applies AWS-specific host/resolver behavior. | Not carried over | Carry over only if/when AWS support is active, and keep it provider-scoped rather than Service-scoped. |
| `docker` | Installs/configures Docker runtime for roles that need containers. | Not carried over as standalone Service | Use as an internal dependency for Services that need containers. Do not expose directly to operators. |
| `openresty` | Installs/configures host OpenResty for HTTP/TLS proxying. | Not carried over directly | Do not direct-port. Barragan should follow the current production containerized OpenResty proxy-stack model documented in the live architecture references. |
| `ssh-proxy` | Installs legacy SSH proxy scripts and helpers for sketch middle/edge connectivity. | Not carried over directly | Needs separate proxy/channel design work. Follow current production proxy examples and Barragan OPSEC rules, not legacy assumptions. |
| `backflips` | Installs the retired host-managed SSH backflip runtime. | Superseded by the native Backflips capability and upstream `backflips_v2` bootstrap role. | Keep only as historical reference. Barragan applies `backflips_v2`; operators own listener lifecycle through its CLI. |
| `tinyproxy` | Installs/configures Tinyproxy HTTP proxy service. | Not carried over | Candidate for a future proxy/platform Service if still operationally needed. Needs design and operator workflow. |
| `dante-server` | Installs/configures Dante SOCKS proxy service. | Not carried over | Candidate for a future proxy/platform Service. Needs design and operator workflow. |
| `web-check` | Runs/deploys a containerized web checking utility; depends on Docker. | Done as optional Proxy capability metadata | Use only for Red Team infrastructure self-checks: Red Team-controlled websites, DNS records, and exposed web services. Do not use it to scan target/customer websites from RTI. |
| `mythic` | Installs and starts Mythic C2 using Docker-backed scripts/configuration. | Not carried over | Candidate for a future app/container Service, but high complexity and needs explicit work item, threat model, and lifecycle design. |
| `etherpad` | Runs Etherpad collaborative editor using Docker Compose. | Carried as Standard RTI default projection, not yet a first-class Service | Barragan can apply the legacy role through the core capability apply path. It still needs a dedicated collaboration-app Service/capability workflow if operators need post-deploy enable/disable, service placement tracking, and progress-console UX. |
| `elk` | Deploys an Elasticsearch/Logstash/Kibana stack using Docker Compose. | Not carried over | Candidate for future observability/logging design. Too heavy for a simple role carry-over. |
| `logstash` | Installs/configures Logstash service and log pipeline config. | Not carried over | Treat as part of future observability design with `elk`, not standalone carry-over. |
| `loot` | Creates/installs legacy loot/documentation scaffolding under `/loot`. | Superseded | Do not expose in Barragan. Superseded by the essential `engagement-workspace` role, which creates `/engagement/loot`. |
| `engagement-workspace` | Creates the standard Homebase `/engagement` workspace and `/engagement/loot` tree. | Pending upstream PR / Barragan adopted | Essential Homebase capability. Human operators can run it through redteam-infra Ansible; Barragan treats it as canonical and keeps INFRA refresh as a writer/fallback. |
| `sketch-opsec` | Applies OPSEC constraints for sketch middle/edge hosts. | Not carried over | Needs separate sketch-chain OPSEC design. Must preserve Barragan’s rule that sketch middle/edge nodes stay minimally informed. |
| `template` | Skeleton role used to create new Ansible roles. | Not applicable | Do not carry over. It is scaffolding, not runtime behavior. |

## Suggested next tranche

If we continue legacy role carry-over, the next tranche should be handled as a
new platform/proxy service work item rather than added to `Desktop`.

Recommended candidates:

1. `tinyproxy`
2. `dante-server`
3. selected `ssh-proxy` behavior, only after reconciling with the current
   production proxy/channel architecture

Avoid direct-porting `openresty`; Barragan should continue following the current
production containerized OpenResty proxy-stack model.
