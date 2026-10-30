# Barragan

Copyright (c) 2026, Oracle and/or its affiliates.

Barragan is a FastAPI and React control plane for Red Team Infrastructure. It
manages engagement-scoped infrastructure, connection paths, DNS, certificates,
operator access, and optional host capabilities. This source export includes the
core control plane and Go Simple Upload Server support. ATC, LootTool, C2 Observer
and Inference Proxy are delivered in a separate, dependent publication branch.

The provider-keyed workflow remains an opt-in pilot. Existing engagements retain
their recorded source identity; this export does not migrate their state.

## Layout

- `backend/`: API, jobs, integrations, domain services and source tests.
- `frontend/`: React/Vite operator console and source tests.
- `ops/`: generic OpenResty/systemd templates and OCI CLI environment setup.
- `scripts/barragan-admin`: service management and offline account recovery.
- `docs/`: operator and configuration references.
- The enclosing repository owns the Ansible roles and Terraform templates.

## Source and template checkouts

Install the app checkout at `/opt/redteam-infra` or adapt the supplied service
units to your chosen installation root. The units assume the nested app lives
at `/opt/redteam-infra/barragan` and load local settings from
`/etc/barragan/barragan.env`. Run services under a dedicated `barragan` account.
The OpenResty launcher also accepts `BARRAGAN_ROOT`.

Provider-keyed operations require a **separate clean Git checkout** at the exact
public template snapshot:

```sh
git worktree add --detach /opt/redteam-infra-keyed cae68e63b8495f0e6d31dfa4a991f4024f18e58b
```

Set both template roots explicitly in the local environment file:

```sh
BARRAGAN_PROVIDER_KEYED_TEMPLATE_ROOT=/opt/redteam-infra-keyed
BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT=/opt/redteam-infra-keyed
```

The keyed root must stay at `cae68e63b8495f0e6d31dfa4a991f4024f18e58b`; exact revision and complete
tracked provider-file hashes are checked. Do not edit that worktree. The generic
root is independent: on the AI branch it must point to a clean checkout that
also contains the optional Ansible roles, while the keyed root stays pinned.
Historical source identities are retained for existing workspace records.

## Prepare the app

Use Python 3.10 or newer for the backend and a Node.js version supported by
Vite 7 for the frontend. Provide Terraform, Ansible, OpenResty/nginx and provider
CLI dependencies appropriate to your deployment. Review the OCI CLI setup under
`ops/oci-cli-runtime/` if using instance-principal OCI access.

```sh
cd /opt/redteam-infra/barragan/backend
python3 -m venv .venv
.venv/bin/python -m pip install .
cd ../frontend
npm ci
npm run build
```

Configure the deployment before starting services. The repository contains no
operator credentials, runtime database, provider tokens or production inventory.
Required local settings include:

- `BARRAGAN_PARENT_REDTEAM_COMPARTMENT_ID` and
  `BARRAGAN_TESTING_COMPARTMENT_ID`: your approved OCI compartment identities.
- `BARRAGAN_OCI_DEPLOYMENT_TARGETS_FILE` and
  `BARRAGAN_OCI_COMPUTE_PROFILES_FILE`: administrator-maintained JSON registries;
  see the corresponding examples in `docs/`. Production mode retains the
  existing requirement for four approved production target entries.
- `BARRAGAN_DATA_DIR`: a private persistent runtime directory, distinct from
  source and template checkouts.
- `BARRAGAN_CREDENTIAL_MASTER_KEY_FILE`: a private credential-encryption key
  maintained outside source control.
- Provider credentials, approved SSH keys, DNS settings, and optional
  `BARRAGAN_NAMECHEAP_CLIENT_IP`, as required by your configured providers.

The shipped production unit enables authentication and binds the API to
loopback. Access is intended through an SSH tunnel or an appropriately managed
local reverse proxy. Review the supplied units before installing them; installing
units is an operator action and is not performed by this publication.

Use `scripts/barragan-admin users --environment prod --help` for offline account
administration. The relevant service group must be stopped before account
changes. Keep real account names and secret files in local configuration.

## Ingress and host configuration

The public manual `ingress-restrictions` role remains available. Barragan's
provider-keyed path uses its own explicit per-host ingress configuration. Its UFW
bootstrap is opt-in and only for fresh hosts with inactive UFW; existing hosts
require separately reviewed migration. Legacy Terraform paths remain supported.

HTTP/S follows edge -> middle -> proxy front -> site container -> backend.
Backflips listener lifecycle belongs to the Backflips CLI, not the control plane.
See the enclosing repository's legacy/v2 role migration notes before selecting a
Backflips implementation for a host.

## Publication boundary

This publication packages source, reviewed templates and synthetic contract
fixtures. It does not deploy resources, run host playbooks, migrate retained
engagements, distribute optional application binaries, or establish new runtime
acceptance for the public source identity. Existing functional qualification is
separate from the source export. See `COPYRIGHT` and `LICENSE-2.0.txt` for
copyright and licensing; preserve third-party notices.
