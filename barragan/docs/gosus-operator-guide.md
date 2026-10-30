# Go Simple Upload Server (GoSUS) operator guide

This guide covers the supported Barragan workflow for deploying GoSUS to a
running engagement and proving the public upload path.  It is deliberately a
small, repeatable operator procedure; use the current `redteam-infra` checkout
for role implementation details.

## What Barragan manages

GoSUS is a Homebase capability.  The upstream service is named
`go-simple-upload-server.service` and listens on Homebase port `9999` when it
is running.  That is the semantic backend selected in Barragan.  HTTP/S uses
the fixed shared web path; it is not a special edge service and does not need a
separate proxy-stack deployment model.

The public path is shared infrastructure:

```text
client -> selected edge -> selected middle -> selected proxy front OpenResty
       -> per-host site OpenResty -> Homebase GoSUS :9999
```

This is the same front stack used by Static Web.  Each route is selected by its
host, so a GoSUS route and a Static Web route may safely use the same proxy.
For the underlying container and certificate architecture, see
`live-containerized-services-reference.md`.

## Deploy the capability and route

1. In the engagement **Capabilities** page, select the GoSUS row under
   **Homebase** and apply the saved optional-role change to the running core.
   Wait for the capability job to finish and confirm the role reports applied.
2. In **Inbound Channels**, create an HTTP or HTTPS channel on the intended
   edge. Choose **Go Simple Upload Server** as the backend and enter port
   `9999`. For HTTPS, Barragan uses the fixed shared transport
   `edge:443 -> middle:443 -> proxy front:443 -> per-host site:8081 ->
   Homebase:9999`. The proxy-front `:443` hop is TLS/web routing, not a GoSUS
   process bind and not a per-capability sketch listener.
3. Assign the appropriate engagement domain.  For an intentionally
   DNS-independent disposable test, use an opaque synthetic Host value only;
   do not publish work-item, branch, host, or environment names in a route.
4. Apply the channel, then use **Configure** to set the route's request-size
   policy.  The validated GoSUS policy is **500 MB decimal** (`500,000,000`
   bytes).  Do not configure a public route above the backend policy.
5. Retrieve the GoSUS client request-gate value through the route's
   **Configure** view and give it to authorized clients using the displayed
   copy/curl workflow. Do not replace or rotate it merely because it is a
   bearer-formatted client value.

For an existing route, use **Preview Reapply**, review the current channel
plan, enter the displayed confirmation phrase, and choose **Reapply**. Do not
use **Add Inbound Channel** to recreate it. If TLS was already bound, use
**Manage Cert** to rebind the retained certificate after route reapply and
before the public Inspector proof.

GoSUS's own `read_write` bearer value is operator-visible client
configuration. For a Barragan-managed typed GoSUS route, Barragan retains and
enforces that same value in the per-domain OpenResty site before `proxy_pass`,
then forwards it to GoSUS. Missing or incorrect values receive a bland `404`
without reaching GoSUS. Do not infer this protection from a successful upload
alone: perform the absent, wrong, and correct-header checks below.

The selected proxy must be able to reach Homebase TCP/9999 through its host
firewall. That permission is narrow: selected proxy private address, TCP, and
port `9999` only—never a public or broad-subnet Homebase exception. Barragan
converges this rule with the managed route and removes its comment-scoped rule
when the route is removed; do not use a one-time host repair as a substitute
for the normal workflow.

The public request-header gate value is intentionally operator-viewable client
configuration, not a session credential or private key.  Do not rotate it only
because an authorized operator can copy it from the UI.  Provider credentials,
SSH private keys, session material, and private backend authorization remain
secrets and must not be copied to jobs, browser artifacts, or documentation.

## Prove the actual upload path

A successful channel job proves controller reconciliation, not that a client
can upload through every proxy hop.  For promotion-quality evidence, use the
engagement's approved **Inspector** as the public vantage point; never probe a
public edge from `barragan-app`.

1. From Inspector, send a **5 MiB** (`5,242,880` byte) multipart `POST` to
   `/upload` with the route Host and the required authorized request data.
2. Expect HTTP `201`.
3. Through Barragan's normal management SSH path, verify the stored Homebase
   file has the exact expected checksum.
4. Remove the disposable upload fixture once its checksum is recorded.

The GoSUS service's `GET /` can correctly return `404`; that response is not a
failed upload proof.  A status-only route/Inspector check can treat that root
response as reachable, but only the `POST /upload` plus Homebase checksum is
the capability acceptance check.

For a Barragan-managed typed GoSUS route, also prove a missing or incorrect
bearer header receives `404` at OpenResty and does not reach GoSUS. This is
separate from GoSUS's own application authorization.

## Retrieve uploaded files from Homebase

GoSUS stores uploads under `/opt/go-simple-upload-server/files`. Authorized
engagement team members retrieve them by their normal SSH session to Homebase;
this is not a GoSUS service-account or configuration-directory workflow. The
role uses ordinary Unix permissions, not ACLs: the upload root is
service-owned `0775` and the unit umask produces new uploads as `0664`. That
lets ordinary local engagement users traverse and read uploads but not modify
them. Do not add operators to the `go-simple-upload-server` service group and
do not grant access to `/etc/go-simple-upload-server`.

The public request-gate value is an operator-visible bot deterrent, not a
credential. The private backend authorization must remain private.

## Prove shared-proxy coexistence

On the same selected proxy, add a Static Web route with a different Host and
validate it from Inspector.  The Static Web Host should return its expected
`200` response; the GoSUS root Host may return its expected `404`.  Reapply the
GoSUS route policy and confirm both host routes still behave as expected.  This
proves that a GoSUS change has not replaced the shared front OpenResty routing
for Static Web.

## Time and cleanup expectations

Treat a fresh core, Inspector preparation, package installation, and sketch
bootstrap as separate stages.  A fresh multi-node run commonly takes tens of
minutes, and package-manager or apt-lock work on a new image can be quiet for
several minutes while still progressing.  Use persisted job phase/activity
evidence before retrying or tearing down.

For a disposable proof, remove temporary routes/capability fixtures and then
tear down the engagement through the Barragan UI.  The retained Inspector must
verify that retired public endpoints are absent before Barragan destroys it.
Use provider reconciliation to confirm that no Barragan-owned resources remain.
Do not manually delete provider resources merely to hide an incomplete job.

## Related material

- `docs/agent-workspace/verification.md` — browser and live-validation rules.
- `docs/agent-workspace/inbound-channel-regression.md` — release matrix for
  inbound changes.
- `docs/agent-workspace/standard-e2e.md` — full disposable integration run.
- `work-items/WI-0319-full-capability-integration-e2e.md` — completed GoSUS
  capability evidence and its follow-up context.
- `work-items/WI-0331-sk02-dev-one-time-recovery.md` — completed, exceptional
  SK02-dev recovery record; not a normal operator procedure.
- `work-items/WI-0333-managed-http-backend-tls.md` — completed managed TLS
  site implementation and acceptance record.
