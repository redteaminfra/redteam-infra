# Barragan Access Management Model

Barragan owns operator access for Barragan-managed infrastructure. The model separates application identity from managed infrastructure accounts and makes every access change auditable.

## Principles

- A Barragan platform user is immutable. Deactivation changes status, not historical identity.
- Application access and infrastructure access are different concepts.
- Per-engagement membership controls what an operator can do in Barragan.
- Infrastructure access propagation is a recorded job, not an untracked side effect.
- Named operator accounts may be propagated to core infrastructure only.
- Named operator accounts are not propagated to sketch nodes by default.
- Sketch nodes use generic sketch accounts after bootstrap. Legacy
  redteam-infra sketch provisioning may initially connect as root to bootstrap
  those accounts.
- Barragan application privileges and infrastructure-side Linux groups are
  separate concepts.
- Legacy names such as `redteam`, `core`, `volunteer`, and `infra` are not
  Barragan application permission primitives.
- `redteam`, `core`, `volunteer`, and `infra` remain supported
  infrastructure-side Linux groups for managed core hosts.
- Membership in the infrastructure-side `redteam` group grants sudo on managed
  core hosts.

## Core Entities

### PlatformUser

Represents a person or service identity that can act in Barragan.

Fields:

- `id`
- `username`
- `display_name`
- `email`
- `status`: `active`, `deactivated`
- `global_roles`
- `created_at`
- `deactivated_at`

Platform user IDs are stable and never reused.

### GlobalRole

Coarse platform-wide role.

Initial roles:

- `operator`
- `infrastructure_manager`
- `approver`
- `administrator`
- `service_account`

Global roles define broad eligibility. Engagement membership still controls engagement-specific action privileges.

### EngagementMembership

Connects a platform user to an engagement.

Fields:

- `id`
- `engagement_id`
- `platform_user_id`
- `privileges`
- `status`: `active`, `suspended`, `removed`
- `infrastructure_state`: `pending_enable`, `enabled`, `pending_disable`,
  `disabled`, `unknown`
- `created_by_user_id`
- `created_at`
- `updated_at`

Initial privileges:

- `view`
- `operate`
- `approve_destructive`
- `administer`

These privileges control what the user can do in Barragan. They do not map to
Linux groups on deployed infrastructure.

Engagement Team UI does not expose these application privileges. Operators
manage per-engagement Linux group membership there; Barragan application
privileges remain a Global Team concern until a dedicated app authorization
slice revisits that model.

### Infrastructure Linux Groups

Infrastructure Linux groups describe the Unix-side account state Barragan should
apply to managed core hosts for named operators.

Initial groups:

- `redteam`
- `core`
- `volunteer`
- `infra`

New global team members default to `redteam` and `volunteer`, matching the
legacy SSH inventory default. Operators may change the global defaults and may
override them per engagement.

Only the `redteam` group carries sudo policy in v1. The other groups are
classification and workflow groups unless a later explicit work item assigns
additional host policy.

### InfrastructureAccessUser

Represents an account Barragan manages on deployed infrastructure.

Fields:

- `id`
- `engagement_id`
- `platform_user_id`
- `kind`: `core_named`, `sketch_management`
- `username`
- `credential_ref`
- `status`: `planned`, `active`, `deactivated`, `rotating`, `removed`
- `created_at`
- `updated_at`

Rules:

- `core_named` users may map one-to-one to active platform users and target homebase and approved proxy hosts.
- `sketch_management` users are generic accounts used by Barragan automation and, where approved, infrastructure managers.
- The default sketch management account is `user`; it is the non-root account
  used for privileged setup and channel configuration through controlled sudo
  after initial sketch bootstrap has completed. Barragan runs the configured
  upstream sketch bootstrap as root only through `homebase -> proxy -> middle
  -> edge`; that playbook establishes `user`, then Barragan uses `user` with
  sudo to install its independent transport public key for `sketchssh`.
- `sketchssh` is not a management account. It is the minimal runtime SSH
  account used for proxy-owned tunnels such as outbound SOCKS paths.
- `sketch_management` users must not be named operator accounts.

### Sketch Bootstrap Exception

The legacy `redteam-infra` sketch flow reaches new middle and edge nodes as
`root` during initial Ansible bootstrap. That bootstrap creates the generic
`user` and `sketchssh` accounts and applies baseline host configuration. This
is different from normal operator or Barragan app-host access:

- root SSH is acceptable only as part of the inherited sketch bootstrap path;
- Barragan must not use direct app-host SSH to middle or edge public addresses;
- post-bootstrap management should use the generic `user` account where the
  workflow supports it;
- runtime tunnels should use `sketchssh`; and
- named operator accounts must not be propagated to sketch nodes.

### CredentialRef

Reference to secret material without storing secret values in Barragan's relational rows or rendered Git artifacts.

Fields:

- `id`
- `purpose`
- `secret_store`
- `secret_path`
- `public_fingerprint`
- `status`: `active`, `rotating`, `revoked`
- `created_at`
- `rotated_at`

Private keys, passwords, API tokens, and session material are never rendered into Git.

### LocalCredential And ApplicationSession

Barragan's initial production identity source is its own database. A local
credential belongs one-to-one to an immutable active `PlatformUser`/Global Team
member. Passwords use Argon2id; temporary username passwords exist only for
first-login bootstrap and must be replaced before application access.

Application sessions are random opaque tokens. Barragan stores only session and
CSRF token hashes and sends the session in a host-only HttpOnly SameSite=Strict
cookie. Sessions expire after 12 hours absolutely or two idle hours, and are
revoked on password change/reset or account disable. Production and dev/test
use distinct cookie names because cookies are scoped by host rather than port.

The outer SSH key/tunnel boundary controls who can reach Barragan. The inner
login identifies and authorizes the user. API clients use the same login,
cookie, and CSRF protocol as the browser; Barragan does not issue JWTs or
require request-signing keys.

### AccessPropagationPlan

Plan for applying an access state change to infrastructure.

Fields:

- `id`
- `engagement_id`
- `deployment_revision_id`
- `requested_by_user_id`
- `status`: `planned`, `queued`, `running`, `succeeded`, `failed`, `cancelled`
- `target_hosts`
- `changes`
- `job_run_id`
- `created_at`

Plans are dry-run capable and must be attached to job runs before execution.

### AccessAuditEvent

Append-only record of access decisions and propagation outcomes.

Fields:

- `id`
- `actor_user_id`
- `action`
- `target_type`
- `target_id`
- `engagement_id`
- `summary`
- `metadata`
- `created_at`

## Authorization Model

Authorization combines:

1. Platform user status.
2. Global role eligibility.
3. Per-engagement membership privileges.
4. Action-specific approval state.

Minimum action classes:

- `view`: read engagement state, topology, rendered artifacts, and job history.
- `operate`: create revisions, run non-destructive jobs, repair routes, and rotate non-destructive config.
- `approve_destructive`: approve archive, destroy, retire, destructive route changes, or access revocation at scale.
- `administer`: manage engagement settings, members, template publication, provider settings, and access policy.

Destructive actions should require both an eligible actor and an approval record. The same user may request and approve only if policy explicitly allows it.

## Propagation Model

Access propagation is a job-backed workflow:

1. User or policy change is recorded in Barragan.
2. `AccessService` computes desired infrastructure account state.
3. Barragan creates an `AccessPropagationPlan`.
4. Plan is reviewed or approved if required.
5. `JobService` runs the propagation job in dry-run or live mode.
6. Integration adapters apply account/key changes through the deployment's management path.
7. Job events and access audit events record each target result.

Membership infrastructure state is operator-facing:

- `Pending Enable`: the operator should be enabled or updated on core hosts.
- `Enabled`: Barragan has evidence that the desired account state is live.
- `Pending Disable`: the operator should be disabled on core hosts.
- `Disabled`: Barragan has evidence that login has been disabled while
  preserving the Unix account and files.
- `Unknown`: Barragan cannot recover the live access state from available
  records.

Removing an operator from an engagement preserves the membership record and
moves the infrastructure state toward `Pending Disable`. It does not delete
history, Unix account state, or audit evidence.

Target behavior:

- Homebase receives named core users for active engagement members who need core access.
- Homebase also reconciles the legacy redteam-infra VNC baseline for active
  users: `/etc/skel` supplies the XFCE/TigerVNC startup files and
  `vncserver@.service`, and Team access apply ensures each active user's home
  has those files, a VNC password, and an enabled UID-derived VNC user service.
  The remote display is `UID - 6000 + 1`, so the remote TCP port is
  `5900 + (UID - 6000 + 1)`.
- Barragan persists an operator UID when a new Global Team member is created,
  including imports. Blank creation assigns above the highest reserved UID,
  starting at 6000 and stopping at 64999; automatic assignment never fills gaps
  or reuses a previous high-water range. Explicit valid UIDs remain supported.
  Deactivated members retain their assignments. Blank edits/imports preserve
  existing values; existing null values require reviewed reconciliation.
  Barragan renders the saved UID into core access Ansible. It must not silently
  change an existing host account UID during normal access propagation; UID drift can affect file
  ownership, running sessions, and VNC port expectations. Early pilot hosts
  that were created before UID preservation may require one-time manual repair,
  but new deployments should converge through the desired UID data.
- Proxy hosts may receive named core users only when the engagement policy allows proxy SSH access.
- Middle and edge nodes receive only generic sketch management accounts.
- Middle and edge nodes must not receive named operator accounts or the full
  engagement team list.
- Deactivation removes or disables future access while retaining audit history.
- Key rotation creates new credential refs and propagation jobs rather than mutating old audit records.

## OpSec Enforcement

Access propagation to sketch must respect the same management path as configuration automation:

- Barragan reaches homebase first.
- Barragan reaches proxies through homebase, using proxy private addresses.
- Barragan reaches middle nodes through homebase and the selected proxy.
- Barragan reaches edge nodes through homebase, the selected proxy, and their assigned middle.

Direct Barragan-to-proxy-public-SSH, Barragan-to-middle, and Barragan-to-edge access are not supported management paths.

## Git Rendering

Rendered Git artifacts may include access intent and credential references:

- `access/core-users.yaml`
- `access/sketch-management.yaml`
- public key fingerprints
- secret store references
- propagation target summaries

Rendered artifacts must not include private keys, passwords, tokens, or raw secret values.

## Legacy Assumptions

Barragan does not import legacy engagements in v1 and does not inherit legacy
group/tag semantics as application permissions.

Legacy account names, SSH key practices, and Linux groups can inform migration
runbooks and core-host propagation. Barragan's v1 application model starts with:

- immutable platform identities
- explicit engagement membership
- action-class privileges
- infrastructure Linux groups as a separate core-host access concept
- generic sketch management users
- auditable propagation jobs

## Initial API Surface

Suggested future resources:

- `GET /api/users`
- `GET /api/users/{user_id}`
- `POST /api/users/{user_id}/deactivate`
- `GET /api/engagements/{engagement_id}/members`
- `POST /api/engagements/{engagement_id}/members`
- `PATCH /api/engagements/{engagement_id}/members/{membership_id}`
- `POST /api/engagements/{engagement_id}/access/plan`
- `POST /api/access-plans/{plan_id}/jobs/apply`
- `GET /api/access-audit-events`

Live propagation must remain feature-gated until provider and host-access adapters are approved.
