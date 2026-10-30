# Live Containerized Services Reference

This note captures the SK01 and OF02 proxy-side service patterns observed during
read-only inspection. It exists so future Barragan work can use the live
deployment model without repeatedly reconnecting to active engagement
infrastructure.

This is the canonical proxy-side architecture reference for Barragan. The
host-installed OpenResty and HTTP-01 workflow from legacy redteam-infra material
and `spec/README_TLDR.html` is legacy and must not be used as the target model.

Do not copy credentials, bearer tokens, private keys, or route-specific
operational secrets from live hosts into this document. Some live web configs
contain token-gated paths; those are intentionally described only as
token-gated locations.

## Scope

Observed examples:

- `proxy01-sk01-prod`
- `proxy02-sk01-prod`
- `proxy01-of02-prod`
- `proxy02-of02-prod`

Related durable decisions:

- `decisions/ADR-0011-live-rti-channel-patterns.md`
- `docs/of02-finished-deployment-reference.md`

## Service Boundary

Web and SSH Backflips are separate service families.

Web services are proxy-side Docker/OpenResty compositions rooted under
`/opt/web`. They own static content, reverse-proxy config, SNI/HTTP routing,
and optional route-specific handlers.

SSH Backflips are proxy-side OpenSSH server containers with companion `autossh`
containers rooted under `/opt/backflips`. They own reverse SSH/backflip service
listeners and must not be treated as generic nginx stream routes.

Raw TCP/UDP inbound channels bind edge and middle routing to a selected service
listener. HTTP/S is different: it uses the fixed shared web transport described
below. Services own their process/container and local configuration; web
channels select a domain route into the proxy front rather than creating a new
sketch listener.

### Disposable raw-TCP route proof

Before assigning a raw TCP route to a real capability, validate the managed
edge -> middle -> proxy -> termination-host path with a **temporary listener**.
The listener receives a unique marker, the selected edge sends that marker
through the route, and the listener exits immediately after the match. An
Inspector then performs the separate public-ingress TCP-connect check.

This is a test route, not a shortcut around a service. It must use a dedicated,
currently unused high backend port (for example, `18080` only after confirming
that it is free). Do not target SSH `22`, a port already held by GoSUS, Static
Web, or another capability, or any existing production listener. Once both
checks pass, remove the temporary route and its provider/host firewall rules;
only then may the real service claim that port and receive its own route.

Public and relay ports have separate purposes:

- `80` and `443` belong to the shared web ingress and are not raw-TCP test
  ports.
- `2222/tcp` is a standard edge ingress port, but it is reserved while a
  Backflips listener uses it. A temporary raw-TCP proof may use it only when no
  Backflips listener or other channel owns that edge port.
- The `8000-8080` range is Barragan's private relay range. Never select a
  relay port as a public listener or a termination-service port.

Port availability is an operational precondition, not an assumption: check the
selected edge, middle, proxy, and termination-host claims before applying a
temporary route. Never stop or displace a real service merely to make a test
listener bind.

An inbound HTTP/HTTPS channel may also own a simple whole-Host request gate at
the selected site container. The gate maps an operator-selected request header
to one retained `Bearer <token>` value, returns 404 before proxying when the
value does not match, and remains independent of the backend capability. New
values are 8–20 URL-safe characters. Each selected site HTTP context renders
one `map_hash_bucket_size 512` directive before its gate map instead of relying
on the platform default. More specific path, method, backend-token, or
application behavior continues to belong to a capability or a later route
access-policy feature.

For shared HTTP/HTTPS web ingress, removing one channel removes Barragan's
channel record but retains the baseline edge/middle/proxy web pass-through when
other web routes may share the same listener. Removing the Static Web service is
the service cleanup step; removing the sketch/core infrastructure is the final
resource cleanup step.

## Web Layout

Live proxy hosts use Docker with a shared front OpenResty container and one
OpenResty container per domain or site.

Barragan uses the independent **site name** for `<site>`; the DNS hostname is a
separate setting. Historical upstream `openresty-v2` deployments commonly use the
literal domain name as that directory. Both use the same `/opt/web` host layout;
Barragan does not rename a site's directory when its hostname changes. The
separate upstream `/dropbox` NFS share is not the web document root.

New Barragan Static Web deployments create `/opt/web/README.md` with the directory
and host/container mount guide after the owned-stack preflight. It stays outside
served content, preserves an existing guide, and participates in apply rollback.
Website files belong under the selected site's `html/`; generated configuration
should be changed through Barragan. Current Static Web Apply reviews the files
and defaults to Preserve. Explicit Restore replaces only `index.html`, retaining
other assets. Separate API content publishing can replace matching files; keep
content backups. See the [content review process](processes/static-web-content.md).

Common paths:

- `/opt/web/docker-compose.yml`
- `/opt/web/nginx.conf`
- `/opt/web/conf/*`
- `/opt/web/streams/*`
- `/opt/web/<site>/conf/*`
- `/opt/web/<site>/conf/00-request-header-gate-00-runtime.conf`
- `/opt/web/<site>/conf/00-request-header-gate-map.conf`
- `/opt/web/<site>/conf/request-header-gate.inc`
- `/opt/web/<site>/html/*`
- `/opt/web/aws.conf`
- `/opt/web/leaseweb.conf`
- `/opt/web/m247.conf`

The current Barragan front `proxy` container publishes `80:80` and `443:443`.
It mounts `/opt/web/nginx.conf` at `/usr/local/openresty/nginx/conf/nginx.conf`,
and the host `http/`, `tls/` and `streams/` directories at their matching
`/etc/openresty/` paths, all read-only. Historical upstream stacks may mount
`/opt/web/conf` at `/etc/nginx/sites-enabled` and `/opt/web/streams` at
`/etc/nginx/streams`; those are not Barragan's current front-container paths.
Barragan retains `/opt/web/conf` for compatibility; active front maps use the
`http/`, `tls/` and `streams/` directories. Edge/middle transport also uses
`/etc/nginx/streams` on those hosts, independently of proxy container mounts.
When Barragan changes the shared front proxy config, the Static Web workflow
recreates the `proxy` container before validating and reloading OpenResty so the
container observes the updated bind-mounted config.

Each site container mounts only the site-specific config and content:

- `/opt/web/<site>/conf` into OpenResty site config
- `/opt/web/<site>/html` into the document root

Live examples include one container per campaign domain, plus `proxy` and
`certbot` helper containers.

The Barragan target keeps these service boundaries while making ownership
explicit: `/opt/web/.barragan-stack.json` identifies a Barragan-owned stack;
unmarked stacks are not adopted or rewritten.

## Web Routing

### Fixed upstream HTTP/S transport contract

The upstream Redteam-infra web path is layered and uses a small, established
port set. It is **not** a generic per-capability TCP forwarding mechanism.

```text
Internet client
  -> selected edge :80 or :443
  -> selected middle :80 or :443
  -> selected proxy front OpenResty :80 or :443
  -> Host/SNI-selected site OpenResty container :8081 (Docker network only)
  -> private Homebase HTTP service, when the site has a backend route
```

- Edge and middle use Nginx `stream` as L4 TCP relays. They do not terminate
  TLS, decide the requested Host, or host a per-capability web listener.
- For HTTPS, the edge emits one PROXY-protocol header; the middle forwards the
  stream unchanged; the selected proxy front accepts it and uses TLS SNI to
  select the site container.
- The shared proxy front owns host `:80` and `:443`. No capability, including
  GoSUS, may bind proxy `:443`.
- Site `:8081` is an internal Docker-network port, not a port to expose or
  relay through sketch. A Homebase-backed capability uses its own private
  backend port; GoSUS uses Homebase `:9999`.
- `2222/tcp` is the separate traditional SSH/Backflips transport, not part of
  the web path.

Consequently, use the generic raw TCP/UDP route allocator only for raw
channels. Never apply its high-port test or relay design to HTTP/S, Static Web,
certificate, or GoSUS work.

The live `streams.conf` pattern routes HTTPS by SNI:

- edge accepts public traffic and emits a single PROXY protocol header for
  OpenResty-aware modes;
- middle forwards raw TCP and does not add another PROXY header;
- proxy front OpenResty accepts PROXY protocol;
- the front proxy routes to a domain container;
- the domain container terminates TLS and serves content or proxies selected
  paths to homebase services.

Canonical HTTPS data flow:

```text
client -> edge stream -> middle stream -> proxy:443
       -> front OpenResty SNI router -> site:8081 -> TLS termination
```

HTTP port `80` is also handled by the front proxy. Legacy deployments commonly
used it only for HTTP-to-HTTPS redirects, but Barragan-managed Static Web uses a
Host-header map on the shared front proxy so multiple edge listeners can share
proxy port `80` and route to different site containers. Production domain
containers also contain route-specific `location` blocks, blocklist includes,
and token-gated locations. Those path-level behaviors are service logic, not
generic inbound channel logic.

Barragan's optional whole-Host bearer gate is intentionally narrower than
those legacy path-specific examples. It is installed in the selected site
container before backend proxying and is retained as engagement-scoped route
configuration. The shared front router must not receive the token or make the
authorization decision.

### Front and site OpenResty responsibilities

The proxy-side `/opt/web` stack has two different OpenResty roles.

The shared front OpenResty container, usually named `proxy`, is the proxy-host
ingress router. It publishes host ports `80` and `443`, receives the stream from
the selected middle node, accepts the single PROXY protocol header emitted by
the edge node, and uses SNI to select a site container. For HTTPS, it should not
terminate the campaign domain TLS session. It should inspect the TLS ClientHello
with `ssl_preread` and forward the still-encrypted stream to the selected site
container, for example:

```nginx
stream {
    map $ssl_preread_server_name $http_backend {
        example.com example:8081;
    }

    server {
        listen 443 proxy_protocol;
        resolver 127.0.0.11;
        ssl_preread on;
        proxy_pass $http_backend;
    }
}
```

The site OpenResty containers are domain-specific HTTP/TLS handlers. They
listen on the Docker network, typically on `8081`, and terminate TLS for their
domain. A site container can serve static content, reverse-proxy selected paths
to services on homebase, or combine both behaviors. It is the right place for
domain-specific route policy such as decoy content, blocklists, token-gated
paths, user-agent gates, custom headers, WebSocket upgrade handling, and long
timeouts.

In short:

```text
front OpenResty container = shared SNI router
site OpenResty container  = per-domain web server and/or reverse proxy
```

An inbound channel should deliver HTTPS traffic to the selected proxy's front
OpenResty listener. It should not target a site container directly, and it
should not copy the proxy-side web route catalog to edge or middle nodes.

### Request-source attribution boundary

The edge emits one PROXY-protocol header and the selected middle forwards the
TCP stream unchanged. The shared TLS front needs Nginx's optional
`ngx_stream_realip_module` to safely use that header as its effective source
when it emits a new PROXY header to a per-domain TLS site. The standard
OpenResty image currently used by Barragan does not include that module.

Consequently, the current HTTPS site and backend cannot claim an independently
verified original-client address. OF02's live front consumes the one
edge-supplied PROXY header and its site containers listen with `listen 8081
ssl`; legacy `real_ip_header proxy_protocol` and `$proxy_protocol_addr`
references there are therefore not evidence that a site received a second
header. Barragan's managed shared front currently re-emits a replacement PROXY
header to its own site containers, which listen with `listen 8081
proxy_protocol`; without `ngx_stream_realip_module`, that replacement
identifies the selected middle rather than the original Internet client.
Neither variant may label the value as a verified original-client address. For
plain HTTP Static Web routes, the shared front supplies the edge-derived
address in `X-Real-IP`, which the site logs; direct local maintenance traffic
falls back to its peer address. Barragan must not broaden trust to all sources
merely to make TLS logs look more specific. WI-0336 tracks a future
Redteam-infra-aligned, pinned shared-front artifact or another reviewed
upstream-supported solution; it is an observability improvement, not a
prerequisite for inbound delivery, TLS, Static Web, or GoSUS.

Managed sites must also leave global OpenResty directives to the stock base
image. In particular, do not redeclare `map_hash_bucket_size` in a mounted
per-site `conf.d` directory: the base configuration already owns that global
setting, and a duplicate prevents the site container from starting.

The shared front's HTTP Host map and TLS SNI stream map must both include the
managed `tls/*.map` route set. A Static Web reconciliation may rebuild the
shared front, so omitting that include from its renderer would make existing
HTTPS backend hosts fail their TLS handshake even though their site containers
are still healthy.

### Homebase-backed HTTP services

Homebase-hosted services such as Mythic, MeshCentral, upload servers, or other
HTTP tooling follow the same edge and middle route. The difference is inside
the selected site container: instead of only serving files from
`/opt/web/<site>/html`, the site config defines upstreams for homebase services
and proxies selected paths to those upstreams.

The resulting request path is:

```text
client
  -> edge stream
  -> middle stream
  -> selected proxy front OpenResty :443
  -> SNI-selected site OpenResty container :8081
  -> selected homebase service host:port
```

A representative site config shape is:

```nginx
upstream homebase_app {
    server 192.168.0.10:8085;
}

server {
    # Barragan's managed front emits a replacement PROXY header. Without
    # stream real-IP support this identifies the selected middle, not the
    # original Internet client. A certificate overlay adds `ssl` here.
    listen 8081 proxy_protocol;
    server_name example.com;
    root /var/www/html/example.com;

    real_ip_header proxy_protocol;
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /app/ {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://homebase_app/;
    }
}
```

Services that rely on WebSocket or long-lived HTTP connections need
service-specific location handling in the site container, for example
`proxy_http_version 1.1`, `Upgrade` and `Connection` headers, and longer
read/send timeouts. Those details belong to the service profile or capability,
not to the generic inbound-channel renderer.

This is the model Barragan should use for future non-static web capabilities:
the capability owns the homebase service placement and per-domain site config;
the inbound channel owns only the edge and middle route into the selected
proxy's front listener; the certificate binding owns the TLS material consumed
by the site container.

The same ownership boundary applies when the final Homebase HTTP process is
operator-managed rather than a packaged capability. Selecting HTTPS with a
Homebase termination target retains the operator-selected backend port, while
Barragan records the effective public transport as proxy `:443`, creates a
stable per-domain site on Docker-internal `:8081`, and persists that site as the
certificate target. The backend process does not need to own a Barragan
capability record and must not be described as owning TLS. Existing older
records that represented the same route as direct HTTPS-to-Homebase are
normalized only when explicitly reapplied; raw TCP passthrough remains a
separate mode.

The channel-owned site is the certificate endpoint. Certificate binding must
therefore depend on verified ownership of that site, not on the existence of a
packaged capability. A temporary Python HTTP server or another
operator-managed listener is a valid development backend once its exact port
and restrictive Homebase firewall rule are recorded. If a legacy or manually
recovered route is already serving TLS but lacks the persisted site record,
repeatedly running the normal bind action is unsafe: the action expects an
unbound config that it can transform. Use an explicit recovery/reconciliation
workflow that verifies the site, certificate paths, backend, and Inspector
result before recording the binding. WI-0379 tracks that product workflow.

### GoSUS on the shared web path

GoSUS is one current Homebase-backed HTTP capability.  Its upstream systemd
unit is `go-simple-upload-server.service`, it listens on port `9999`, and its
site container proxies its upload path to that Homebase service.  The route
uses the shared front OpenResty architecture above; it must not replace Static
Web routes sharing the selected proxy.  The human deployment, request-size,
Inspector upload, and cleanup procedure is in `gosus-operator-guide.md`.

## Certificate Model

The production proxies share `/etc/letsencrypt` and `/var/www/certbot` volumes
between the front proxy, site containers, and a Certbot helper. Their observed
12-hour webroot renewal loops currently fail HTTP-01 and do not reload site
containers after renewal. Barragan does not reproduce that failure mode.

Barragan uses DNS-01. It keeps the Namecheap credential and ACME account on the
control plane, creates and removes `_acme-challenge` TXT records with full-record
preservation, and waits for authoritative propagation. The selected proxy
generates and retains the private key; Barragan receives a CSR and returns only
the public certificate and chain. No port-80 support route is required for
certificate issuance or renewal.

Certificate lifecycle is exposed through the engagement **Certificates**
workspace. A certificate asset may contain an apex name, a wildcard, or up to
100 assigned DNS identifiers, but it belongs to exactly one proxy. Inbound
channels expose only route TLS status and an explicit binding selector. An
HTTPS route can therefore be applied as `TLS Unbound` and bound later without
coupling route creation to issuance.

Managed bindings rewrite only the selected site's OpenResty configuration to
reference the asset's stable `current` version paths, recreate that site
container, validate its configuration, and reload it. Renewal atomically moves
the stable link while reusing the private key; reissue creates a new key. A
successful issuer revocation deliberately leaves consumers serving and marks
the asset and bindings critical until an operator reissues or replaces it.

The shared named certificate volume survives replacement of the front
OpenResty container when the replacement mounts the same volume. Before
reissuing after a container problem, list only the retained lineage filenames,
inspect public certificate metadata, verify that the certificate and private
key public components match without printing key material, and confirm the
stable `current` symlink. Reissue only when the proxy-held key or public
certificate is actually absent or invalid.

Operator-driven production renewal, reissue, and revocation use an explicit
confirmation panel in the Certificate Manager. Barragan displays the exact
engagement-scoped phrase, keeps the action disabled until it matches, and sends
the value with the normal lifecycle request. Operators should not bypass this
guard with a direct API call. Scheduled renewal remains non-interactive because
it is initiated by Barragan's certificate scheduler rather than an operator.

External certificate uploads contain public material only. Barragan parses and
discards that PEM and records an expected-certificate binding; it cannot deploy
or claim lifecycle control over an external private key.

## Legacy Comparison

| Concern | Legacy redteam-infra | Barragan target |
| --- | --- | --- |
| OpenResty | Host `openresty.service` | Docker front plus site containers |
| Public listeners | Host process owns 80/443 | Front container publishes 80/443 |
| TLS termination | Host site block | Selected site container on 8081 |
| Certificates | Host Certbot lineage | Shared proxy certificate volume |
| ACME challenge | HTTP-01 through the edge path | DNS-01 through Barragan/Namecheap |
| Renewal | Host/manual or failing sidecar loop | Barragan-scheduled audited workflow |

## Backflips Layout

Current `backflips_v2` uses `/opt/backflips` as the proxy-side runtime root.
Ansible bootstraps the directory, dependencies, `flip` runtime user, default
config, and `/opt/backflips/etc/authorized_keys`. Listener orchestration is
owned directly by operators using the Backflips CLI, not by Barragan and not by
Barragan-generated generic inbound-channel routes.

The role creates `backflips.conf` only when it is absent, then reconciles the
`middleKeyPath` value from the existing `sketchkey` role variable. This keeps
the default `/opt/ssh-proxy/keys/sketchkey` compatible while allowing Barragan
to supply `/opt/ssh-proxy/keys/<engagement>-sketch`. Reapplying Ansible does not
replace the listener sections persisted by the CLI.

Each listener is a separate Docker Compose project under:

```text
/opt/backflips/containers/<listener-id>/docker-compose.yml
```

Each project has paired containers:

- `backflip_<name>` OpenSSH server container exposing internal `2222/tcp`
- `autossh_<name>` companion container that maintains a reverse SSH path

Common paths:

- `/opt/backflips/sshbackflip.py`
- `/opt/backflips/containers/<listener-id>/docker-compose.yml`
- `/opt/backflips/etc/backflips.conf`
- `/opt/backflips/etc/ssh/<listener-id>`
- `/opt/backflips/etc/authorized_keys`
- `/opt/ssh-proxy/keys/<engagement-name>-sketch`

The `autossh_*` container mounts engagement-scoped sketch key material and
establishes a reverse `-R 2222:listener-<listener-id>:2222` style path through
the sketch chain. The listener container gets a DNS-safe `listener-*` network
alias because Docker/container DNS can be fragile with underscore-heavy
container names. That makes Backflips service-aware reverse-channel work, not a
generic `proxy:2222 -> proxy:2222` nginx stream route.

The public-facing listener mounts only its own writable configuration
directory. The packaged `sshd_config` and canonical authorized-keys file remain
outside that writable mount. Backflips copies them into the listener directory
at creation time and atomically propagates newly generated victim keys to all
managed listener copies.

The upstream sketch playbook establishes a broad compatibility baseline in an
SSH `Match User sketchssh` block:

- `AllowTcpForwarding remote`
- `GatewayPorts yes`

This does not grant the same forwarding behavior to root or ordinary operator
accounts. Barragan then applies an early, role-specific OpenSSH drop-in during
its post-bootstrap transport-key play. Every selected edge receives:

- `AllowTcpForwarding yes` (local SOCKS plus remote Backflips forwarding)
- `GatewayPorts yes`

Middle nodes instead use `AllowTcpForwarding local` and `GatewayPorts no`, which
preserves the direct jump to the edge without publishing reverse listeners on
the middle. The drop-in loads before the upstream main configuration, so the
role-specific policy wins without editing the upstream checkout. These settings
are applied during sketch bootstrap, so edges added after Backflips is deployed
are also Backflips-ready.

After Barragan has deployed and configured the capability, an operator invokes
listener creation on the selected proxy with IP addresses:

```sh
sudo python3 /opt/backflips/sshbackflip.py listener add \
  --name <listener-name> \
  --callback-host <edge-public-ip> \
  --middle-ip <middle-public-ip> \
  --port 2222 \
  --middle-key-path /opt/ssh-proxy/keys/<engagement-name>-sketch
```

The expected public validation is: an Inspector connects to the edge public IP
on the Backflips callback port, and operators confirm the proxy-side
`backflip_<listener-id>` / `autossh_<listener-id>` containers are running and
the internal listener probe returns an SSH banner with `probe_rc:0`. After test
validation, delete the test listener so the edge does not remain exposed on
`2222/tcp`.

`listener add` requires two consecutive healthy observations of both paired
containers before persisting success. `listener list` reports the pair as
degraded when either side is missing, exited, or restarting. Startup and config
persistence failures roll back the incomplete project; a Compose teardown
failure preserves the project and listener record for troubleshooting.

## Barragan Implications

- Web service work should start with a `web-static` service that writes content
  under `/opt/web/<site>/html` and config under `/opt/web/<site>/conf`.
- The current front reads `/opt/web/nginx.conf` and the `http/`, `tls/` and
  `streams/` directories. `/opt/web/conf` is retained for compatibility.
- DNS records and certificate assets are managed separately through Barragan's
  DNS and Certificates workspaces; issuance uses DNS-01.
- Backflips is a separate capability workflow because the service owns the
  `2222` listener and reverse SSH path.
- Barragan must target proxy hosts through homebase for service apply and must
  not add sketch middle or edge nodes to proxy-side service inventories.
- Barragan installs the engagement-scoped transport key, supplies the upstream
  `sketchkey` role variable, and may render a unique deployed middle as the
  default. It does not expose listener add/list/log/delete controls.
- The copied-module cloud-init overlay applies role-specific forwarding
  readiness to every new middle and edge, including edges added after Backflips
  was deployed.
- Sketch nodes should receive only minimal per-channel route config. They should
  not receive `/opt/web`, `/opt/backflips`, full service inventories, route
  catalogs, provider credentials, or operator documentation.
