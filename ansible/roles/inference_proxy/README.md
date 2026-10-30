# Inference Proxy

Installs the OCI OpenAI-compatible inference service on an Ubuntu Homebase.
The listener is always `127.0.0.1`; default port is `8787`. The role installs
no public routes and creates no agent tokens, IAM policies or dynamic groups.

## Inputs

| Variable | Required value |
| --- | --- |
| `inference_proxy_source_archive` | Absolute controller path to a reviewed, flat `git archive --format=tar.gz COMMIT` artifact |
| `inference_proxy_source_sha256` | SHA256 of that exact artifact, 64 lowercase hex characters |
| `inference_proxy_source_revision` | Full source commit, 40 lowercase hex characters |
| `inference_proxy_region` | OCI inference region; defaults to `us-chicago-1`, independently of the compute region |
| `inference_proxy_compartment_id` | Model compartment OCID; do not assume it is the compute compartment |
| `inference_proxy_port` | Unprivileged loopback port, 1024–65535; default `8787` |

Accepted target inputs: Ubuntu 22.04 or 24.04, systemd, Python 3.10 or newer.
Native qualification covers Ubuntu 24.04 installation without OCI access,
unchanged reapply and same-source-revision repair of a missing check command.
Ubuntu 22.04 is an unqualified candidate target. Cross-release upgrades,
issued-key/nonempty-usage preservation and authorized inference remain
unverified; do not treat local readiness as release acceptance. The
controller needs Python and Ansible; the target needs apt and Python package
index access. Source is supplied by the controller without copying SCM
credentials to Homebase. The archive checksum and git-archive revision are
checked before target changes; unsafe members and unexpected package layout
are rejected. The checksum must come from the reviewed release artifact, not
be calculated from an untrusted download immediately before installation.

The application stays in its own repository. Supply only a source revision
approved for distribution and deployment; this role does not vendor or grant
a license to application code.

## Service and data

- Read-only preflights precede apt, source delivery, configuration and service
  changes. An occupied port must be the existing service's IPv4 loopback socket;
  foreign/wildcard/IPv6 ownership is not adopted or stopped. The Linux proc socket
  tables and systemd MainPID are checked; uncertainty fails closed. Adoption
  additionally requires the exact canonical server command (no alternate path,
  wrapper or arguments), exact `INFERENCE_PROXY_CONFIG` environment binding in
  both the unit and running process, no environment files, and an existing
  regular, non-symlink canonical configuration. A missing/stale canonical config
  is not adopted in place of a running alternate-config service. A running unit
  without the requested listener is also refused, even if that port is idle.
  Every loaded preexisting unit must have the canonical command/config binding
  and original canonical config, even when stopped with an idle port. Only the
  running-process environment check depends on a positive PID. Masked or unknown
  load states require manual recovery. Idle first installs with a genuinely
  missing (`not-found`) unit still need no existing config or application/TOML
  package. Unit identity is rechecked before success. This is
  a preflight, not a port reservation against concurrent administrators.
- Existing listener, inference region and model compartment must match the
  explicit inputs. Mismatches require a separately approved manual migration;
  there is no automatic migration opt-in. The existing runtime Python/TOML reader
  must work to validate retained configuration before package changes. If that
  interpreter itself is missing/broken, restore it through a reviewed manual
  recovery rather than overwriting unread configuration.
- Source: `/opt/inference-proxy/releases/COMMIT`; Python environment:
  `/opt/inference-proxy/venv`. Existing artifacts are retained.
- Configuration: `/etc/inference-proxy/config.toml`, root/service-group `0640`.
  Reapply retains the required loopback listener, region and compartment;
  operator limits, aliases and discovery policy are retained. Nonstandard storage paths or an existing profile/API-key
  authentication configuration require a deliberate operator migration; this
  instance-principal role will not silently convert them.
- Pepper is generated once; an existing database with missing pepper fails
  closed to avoid silently invalidating its keys. SQLite, keys, model cache
  and usage history remain under `/var/lib/inference-proxy`.
  An existing database also requires its original configuration. These checks
  run before changes and do not compute pepper checksums or expose its value.
  Even without a database, any existing pepper must be a regular non-symlink
  file of at least 32 bytes. Dangling links, directories and other nonregular
  paths are rejected before creation or ownership/mode changes.
- Systemd units are supplied by the pinned application. The service runs as
  `inference-proxy`, with its upstream hardening and purge timer.
- Installation/repair runs when source or Python health/commands change.
  Ordinary reapply does not upgrade pip/dependencies or restart the service.
  Dependency versions are recorded at
  `/opt/inference-proxy/installed-dependencies.txt`. Upstream dependency ranges
  are not a fully locked, reproducible wheel set.

Removal is **manual**. Disable the service and purge timer when retiring only
the software; preserve configuration and state. Never use upstream `--purge`
without an explicit operator decision about losing keys and metering data.

## OCI access belongs to the operator

The role uses the Homebase instance principal. The operator configures the
required dynamic-group membership and model-compartment policies in OCI;
Barragan should show the scoped requirements. This role never changes IAM.
Inference authorization and model availability are separate from installation.
Local `/health/ready` checks database readiness, not successful OCI inference.
Supply the same authorized model compartment used by your existing inference
deployment; the role deliberately has no compartment default. A newly created
Homebase has its own instance identity and still needs matching OCI access.

**Qualification candidate:** source branch
`integration/barragan-capability` at
`98838ad67f6e242f281fb2154185f23e07fe1fae` (version 0.2.2) starts without OCI discovery access
and adds sanitized discovery diagnostics in logs and a read-only admin status
command. Its 77-test offline suite passed on Python 3.10 and 3.14. The Ubuntu
24.04 checks above covered the earlier `f2627ae` startup candidate; native
qualification of this exact source and guarded role remains pending. Source-owner
review accepts this pin for packaging/qualification, not production rollout. Original
candidate `fa41ca1` exits on discovery failure without cached data and does not
meet the installed-before-authorization contract. The role never fabricates a
catalog or suppresses readiness failures.

After external IAM configuration, use protected operator access to Homebase:

```sh
sudo /opt/inference-proxy/venv/bin/inference-proxy-admin doctor
sudo /opt/inference-proxy/venv/bin/inference-proxy-admin status
sudo /opt/inference-proxy/venv/bin/inference-proxy-admin model refresh
sudo /opt/inference-proxy/venv/bin/inference-proxy-admin model list
```

Issue agent keys explicitly using the same absolute admin path; keep issued
tokens out of Ansible variables, job logs and screenshots. Verify authenticated
`/v1/models` and an approved bounded inference call before claiming upstream
access works. No billable model probe is run by this role.
`doctor` checks local configuration, pepper and database. `status` reads local
health and discovery timestamps/errors without refreshing models or running
inference. A cached catalog does not prove present OCI access. For service
warnings use `sudo journalctl -u inference-proxy`.

## Verification

Offline helper and syntax checks:

```sh
python3 -m unittest discover -s ansible/roles/inference_proxy/tests -p 'test_*.py' -v
ANSIBLE_ROLES_PATH="$PWD/ansible/roles" ansible-playbook -i localhost, \
  ansible/roles/inference_proxy/tests/syntax.yml --syntax-check
```

These checks do not prove native installation. Disposable Ubuntu acceptance
must cover first install, unchanged reapply, missing-command repair, retained
pepper/keys/SQLite/usage, loopback ownership, unrelated services, missing OCI
authorization and post-policy authenticated inference. Preserve evidence and
remove the disposable infrastructure afterward.

The retained-state regression tests execute the role's actual stat/assert
tasks against temporary local fixtures, never system paths. They require
`ansible-playbook` beside the test interpreter and PyYAML; without these they
are explicitly skipped, not evidence of a passing Ansible guard test. They
verify refusal before a synthetic mutation sentinel and preserve a symlink's
unrelated target bytes, ownership and mode.
