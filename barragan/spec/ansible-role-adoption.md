# Ansible Role and Playbook Adoption Model

## Purpose

Barragan needs a clearer model for adopting existing `redteam-infra` Ansible
content. The goal is not to create new Ansible roles, duplicate existing
playbooks, or delete legacy roles that other users may still depend on. The
goal is to describe existing roles and playbooks with explicit metadata so
Barragan can present them safely, reason about dependencies, and eventually run
approved entry points through its job system.

This document captures the current design direction while the team continues to
think through execution details.

## Core Model

Barragan should keep these concepts separate.

| Layer | Meaning | Example |
|---|---|---|
| Capability | Barragan's operator-facing abstraction. | "Proxy Essentials", "Firefox", "ELK Defaults" |
| Playbook | Existing Ansible orchestration entry point. | `site.yml`, `homebase.yml`, `proxies.yml`, `elk.yml` |
| Role | Existing Ansible implementation component. | `common`, `homebase`, `firefox`, `nfs-client` |
| Template/profile | Barragan's selected baseline for an infrastructure shape. | Standard RTI core essentials and defaults |

Barragan should present capabilities, but the executable implementation may be
an existing playbook, an existing role, or a Barragan-native workflow that uses
Ansible only for bounded host convergence.

## Rules

- Barragan should adapt to operationally valid `redteam-infra` behavior before
  asking `redteam-infra` maintainers to change it.
- Changes requested from `redteam-infra` must be rare, strictly necessary,
  independently justifiable, and useful to manual users as well as Barragan.
- Do not create new Ansible roles merely to make Barragan integration easier.
- Do not reinvent playbooks when an existing playbook already expresses the
  desired orchestration unit.
- Do not delete roles from `redteam-infra` just because Barragan does not use
  them; other users or workflows may depend on them.
- Do not infer safe execution behavior from README prose.
- Use Barragan-owned JSON or YAML manifests as the contract Barragan reads.
- Fail closed: a role or playbook without valid metadata may be listed for
  review, but it must not become executable by accident.

## Classification

Each manifest should classify the capability or implementation unit.

| Classification | Meaning |
|---|---|
| Essential | Always applied for the relevant host class or profile. Operators can see it but normally cannot deselect it. |
| Default | Preselected by the template because the team usually wants it. Operators may deselect it before deployment. |
| Optional | Available but not selected by default. |
| Internal | Dependency or implementation detail, not directly selectable by operators. |

These classifications are template/profile policy, not inherent properties of
an Ansible role. The same role could be default in one profile and optional in
another.

## Roles Versus Playbooks

Existing playbooks should be preferred executable units when they already model
the desired operation.

For example, applying proxy essentials may be better represented as running
`proxies.yml` than as separately asking operators to apply `nfs-client`,
`ssh-proxy`, `dante-server`, `unattended-upgrades`, `proxies`, and related
dependencies.

Roles should only be presented as independently selectable capabilities when
the manifest says they are safe and meaningful to run independently for the
selected host class.

Roles that are pulled by lower playbooks or role dependencies should be
represented as included or internal rather than as separate required operator
clicks.

Role dependencies from `meta/main.yml` should be modeled explicitly in the
manifest data. Examples observed in the bundled legacy snapshot include:

- `elk` depends on `docker`.
- `etherpad` depends on `docker`.
- `proxies` depends on `nmap`.

Internal dependencies such as `docker` should not automatically appear as
operator choices.

## Existing Template Playbook Shape

The real `redteam-infra` template repository is the source of truth for current
Ansible material. Barragan no longer carries a vendored redteam-infra snapshot;
local development uses sibling `../redteam-infra`, and `barragan-app` uses a
full Git checkout at `/opt/redteam-infra` unless
`BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT` explicitly points elsewhere.

The current template contains these primary playbook entry points:

- `site.yml`
- `homebase.yml`
- `proxies.yml`
- `elk.yml`
- `playbooks/reboot.yml`
- `users/user-removal.yml`

The current `site.yml` composes:

1. common roles applied to `all`;
2. `homebase.yml`;
3. `proxies.yml`;
4. `elk.yml`;
5. users playbook material;
6. reboot playbook material.

This means Barragan needs to model both top-level playbook capabilities and
lower playbook or role composition.

## Starting Classification Draft

This list is a starting point for review, not a final execution contract.

### Common Essentials

- `common`
- `molly-guard`
- `logstash`
- `yama`
- `oci`

### Common Defaults

No defaults are currently specified.

### Homebase Essentials

- `nfs-server`
- `homebase`

### Homebase Defaults

- `etherpad`
- `google-chrome`
- `firefox`
- `keepassxc`
- `vs-code`
- `nmap`

### Proxy Essentials

- `nfs-client`
- `ssh-proxy`
- `dante-server`
- `unattended-upgrades`
- `proxies`

### Proxy Defaults

No defaults are currently specified.

### ELK Defaults

- `elk`
- `unattended-upgrades`

## Manifest Direction

Manifests should be authored as JSON or YAML. YAML is likely the friendlier
format for review because the surrounding ecosystem is Ansible, but the schema
should be strict enough that Barragan can validate it deterministically.

Barragan discovers manifests from its packaged application catalog:

- `backend/app/capability_manifests/capabilities/**/*.json|yaml|yml`
- `backend/app/capability_manifests/profiles/**/*.json|yaml|yml`

The configured Redteam-infra checkout supplies implementations only. Barragan
validates manifest role and playbook paths against that pinned source and does
not discover manifests from an upstream `barragan/` directory.

Roles and playbooks without valid manifests may be listed for review, but
Barragan must not make them executable by guessing from filenames or README
prose.

Known Barragan-native capabilities may appear in the same catalog as
redteam-infra Ansible capabilities when Barragan owns their implementation. The
first example is `barragan.static-web-site`, the preferred Barragan-managed
static website workflow. If the selected redteam-infra template contains
`ansible/roles/openresty-v2`, Barragan may also list
`redteam-infra.openresty-v2` as a deployable legacy role capability.

Those two capabilities are alternatives, not layers. Barragan must not mutate
`openresty-v2`-created stacks. Operators choose either the legacy
redteam-infra role capability or the Barragan-native Static Web Site capability
per proxy. They cannot be enabled together on the same proxy because both own
the `/opt/web` front proxy stack and host ports `80/443`; they may be used on
different proxies in the same engagement.

An example playbook capability:

```yaml
apiVersion: barragan/v1
kind: AnsibleCapability

metadata:
  id: proxy-essentials
  name: Proxy Essentials
  description: Apply the existing proxy baseline playbook.

implementation:
  type: playbook
  path: ansible/proxies.yml

scope:
  hostClasses:
    - proxy

classification: essential

composition:
  includesRoles:
    - nfs-client
    - nmap
    - ssh-proxy
    - openresty
    - dante-server
    - unattended-upgrades
    - proxies
    - backflips

operator:
  visible: true
  selectable: false
```

An example independently selectable role capability:

```yaml
apiVersion: barragan/v1
kind: AnsibleCapability

metadata:
  id: firefox
  name: Firefox
  description: Install Firefox using the existing redteam-infra role.

implementation:
  type: role
  role: firefox
  path: ansible/roles/firefox

scope:
  hostClasses:
    - homebase

classification: default

operator:
  visible: true
  selectable: true
```

## Role Capability Execution Model

Standalone Ansible roles require a playbook wrapper to run. Barragan now uses a
generic composed role-runner playbook for core infrastructure deployment:

- Barragan resolves the Standard RTI capability profile for the engagement.
- Essential capabilities are always selected.
- Default capabilities are selected unless the engagement overrides deselect
  them.
- Optional capabilities are selected only when the engagement overrides select
  them.
- Only selected executable manifest-backed Ansible role capabilities are
  included in the composed playbook.
- For real engagement deployments, selected core capabilities fail closed when
  they cannot be resolved into executable role-backed manifests. This keeps the
  Capabilities UI truthful: a checked Standard RTI role should not become a
  no-op because Barragan is pointed at an older template source or a source
  without the required manifests.
- As an adoption bridge, Barragan may project reviewed Standard RTI baseline
  roles from the configured real `redteam-infra` role tree while those
  capabilities migrate to Barragan-owned manifests. This projection is limited
  to known legacy roles and still requires the role directory to exist. A
  declared local manifest, including an invalid one, suppresses the projection.
- Core host classes map to existing inventory groups:
  - `common` -> `pilot_rti`
  - `homebase` -> `homebase`
  - `proxy` -> `proxies`
- Host classes outside the active core deployment, such as `elk`, remain in the
  capability lock but are skipped by the core deployment playbook until that
  infrastructure shape exists.

This avoids creating one-off duplicate playbooks for each role while preserving
the existing role implementation. Roles without manifests or without supported
role execution metadata are visible for review but are not executed through the
capability system. If one of those roles is selected for a real core deployment,
Barragan must stop before mutation or before reporting the selected capability
apply as complete.

## Current Desktop and Utilities Caveat

Barragan already has hard-coded Desktop service behavior for selected homebase
GUI roles, and `nmap` is already carried as baseline tooling. Those may remain
temporarily for compatibility, but they should not define the long-term model.

If the manifest-driven model supersedes them, the existing Desktop and
Utilities-style surfaces may be rolled back, hidden, or replaced by
manifest-backed capabilities.

Etherpad is now part of the projected Standard RTI baseline role set, so core
capability deployment can apply it from the real `redteam-infra` role tree.
That does not yet make Etherpad a first-class post-deploy Service: Barragan
still needs a dedicated collaboration-app capability workflow if operators need
enable/disable controls, durable service placement state, and progress-console
UX outside initial core deployment.
