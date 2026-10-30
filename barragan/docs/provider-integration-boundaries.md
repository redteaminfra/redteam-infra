# Barragan Provider Integration Boundaries

This document defines the first provider integration seam for OCI, Linode, and DigitalOcean. It is a design spike only: no cloud-mutating commands are authorized by this document.

## Boundary Principles

- Barragan's domain model is canonical.
- Provider adapters translate Barragan deployment intent into provider-specific plans and operations.
- Terraform and Ansible are execution backends, not user-facing sources of truth.
- Route, proxy-stack, reverse-channel, access, DNS, certificate, and archive behavior remain Barragan domain concepts even when provider tools execute part of the work.
- Live provider mutation must be feature-gated and job-backed.
- Every provider operation must record a job run, events, inputs, outputs, retries, and artifacts.
- Sketch management must obey the required operator path: Barragan -> homebase -> selected proxy -> selected middle -> selected edge.

## Shared Provider Responsibilities

All provider adapters should expose a common shape:

- `validate_request(intent)`
- `plan(intent)`
- `render_terraform_inputs(plan)`
- `apply(plan, mode="dry_run")`
- `collect_outputs(job_id)`
- `classify_error(error)`
- `recommend_recovery(error, context)`
- `destroy(resource_ref, mode="dry_run")`

Shared concerns:

- region and shape validation
- image selection
- SSH/bootstrap key references
- tags/labels
- network rules
- readiness waits
- retry policy
- error classification
- output normalization
- secret reference handling
- generated artifact rendering
- audit/job event recording

Adapters return normalized provider outputs to the deployment orchestrator instead of leaking raw Terraform/provider response shapes into the domain layer.

## Provider-Specific Responsibilities

## Official Provider API References

Use the official provider documentation as the grounding source before changing
provider adapters, catalog fetchers, credential preflights, Terraform variable
expectations, or lifecycle behavior:

- DigitalOcean API: https://docs.digitalocean.com/reference/api/index.html.md
- Linode/Akamai API docs index for LLMs: https://techdocs.akamai.com/llms.txt

Do not rely on memory for provider API shapes, required scopes, pagination,
region/size fields, or power/delete semantics when these references can answer
the question.

### OCI

OCI owns core infrastructure and Barragan hosting.

Responsibilities:

- compartments
- regions and availability domains
- VCN, route tables, gateways, and subnets
- homebase, proxy, and optional ELK compute instances
- core security lists or network security groups
- boot volume sizing and backup references
- instance-principal authentication for Barragan runtime
- OCI-managed secret references
- capacity and image-health error classification

Known special handling:

- Region capacity errors must be classified separately from invalid configuration.
- The orchestrator may retry in the same region only when the provider classifies the error as transient.
- Region switch requires a new plan or human approval because it changes deployment placement.
- OCI Ubuntu image package-manager health must be checked before normal Ansible configuration continues.
- Broken `apt` state should trigger a remediation runbook or fail with a specific operator action, not a generic configuration failure.

### Linode

Linode is a sketch provider for middle and edge nodes.

Responsibilities:

- middle and edge instances
- region selection
- instance type validation
- image selection
- firewall/open port policy for `22`, `80`, `443`, and `2222`
- SSH key references
- normalized public IP outputs for one middle and one or more edges
- sketch inventory intent
- operator-readable provider resource names such as
  `middle01-<engagement>` and `edge-<engagement>-<region>-01`, with stable
  readable ordinals for multiple edges and suffixes when multiple resources
  would otherwise collide

Linode adapters must not imply Barragan can directly configure sketch nodes. The adapter provisions nodes and returns outputs; configuration follows the modeled management path through homebase and the selected proxy.

### DigitalOcean

DigitalOcean is a sketch provider for middle and edge nodes.

Responsibilities:

- middle and edge droplets
- region selection
- size validation
- image selection
- firewall/open port policy for `22`, `80`, `443`, and `2222`
- SSH key references
- normalized public IP outputs for one middle and one or more edges
- sketch inventory intent
- operator-readable provider resource names such as
  `middle01-<engagement>` and `edge-<engagement>-<region>-01`, with stable
  readable ordinals for multiple edges and suffixes when multiple resources
  would otherwise collide

DigitalOcean adapters follow the same sketch management constraints as Linode.

## Terraform Boundary

Terraform should receive compiled provider intent, not raw UI input.

Input source:

```text
DeploymentRevision.resolved_topology -> ProviderPlan -> TerraformInputBundle
```

Terraform adapter responsibilities:

- render deterministic input files
- run `terraform init/plan/apply/destroy` only through job-backed execution
- capture stdout, stderr, plan files, state references, and outputs
- redact secret values
- classify failures

Early implementation should support render-only and plan-only modes before apply.

Terraform state must not be rendered into Git unless redacted and explicitly designed later. State storage remains a deployment-hosting decision.

Live Terraform-backed jobs should persist bounded, redacted provider diagnostics
when `init`, `apply`, `output`, `destroy`, or cleanup verification fails. The
current event data shape is:

```json
{
  "phase": "apply",
  "terraformDiagnostic": {
    "provider": "linode",
    "command": "apply",
    "returnCode": 1,
    "errorClass": "provider_api_permanent",
    "summary": "short redacted provider error",
    "resourceHints": ["linode_firewall.example"],
    "stderrExcerpt": "bounded redacted stderr"
  }
}
```

Diagnostics may include provider validation errors and Terraform resource
addresses, but must not include credential values, private keys, Terraform
state, or unbounded command output.

## Ansible Boundary

Ansible should receive normalized host inventory and runbook intent from Barragan.

Input source:

```text
DeploymentRevision.resolved_topology + ProviderOutputs + Runbook -> AnsibleInputBundle
```

Ansible adapter responsibilities:

- render inventories that encode jump paths
- run package health checks before normal roles
- run host configuration through job-backed execution
- capture task events and failures
- classify host readiness and package-manager failures

Ansible must not bypass the modeled sketch management path.

## DNS And Certificate Boundary

DNS and certificate integrations are separate from cloud provider adapters because the assumed external DNS provider is Namecheap and certificate automation may require human-in-the-loop behavior.

Responsibilities:

- render DNS/certificate intent
- support dry-run validation
- sync registrar inventory and DNS host snapshots through registrar adapters
- apply supported engagement-scoped DNS host record changes through explicit
  preview/apply workflows
- record pending human action when provider APIs are unavailable
- attach DNS and certificate state to ingress routes

DNS record changes must not be hidden side effects of cloud provider, inbound
channel, or service operations. A service may recommend or link to required DNS
work, but DNS writes remain visible engagement-scoped operations unless a later
work item defines a more integrated workflow with its own operator review step.

## Error Classification

Initial error classes:

- `capacity_exhausted`
- `quota_exceeded`
- `auth_failed`
- `invalid_region`
- `invalid_shape`
- `image_unhealthy`
- `network_unreachable`
- `host_not_ready`
- `package_manager_broken`
- `terraform_failed`
- `ansible_failed`
- `provider_api_transient`
- `provider_api_permanent`
- `manual_action_required`

Recovery recommendations:

- retry same operation
- wait and retry
- switch region with approval
- choose alternate shape
- run package-manager remediation
- request credential or IAM fix
- require human intervention
- fail revision

## Orchestration Flow

Plan-only flow:

1. Compile deployment revision.
2. Build provider plans.
3. Render Terraform/Ansible/DNS/certificate intent.
4. Render Git-visible artifacts.
5. Record job events and artifact refs.

Live flow, once approved:

1. Create job run.
2. Validate provider plans.
3. Provision OCI core.
4. Wait for homebase readiness.
5. Run core package health checks.
6. Configure homebase and proxies.
7. Provision sketch middle and edge nodes.
8. Configure sketch through the modeled management path.
9. Publish egress profiles, ingress routes, proxy-stack, reverse channels, DNS, certificates, and access.
10. Validate paths.
11. Record outputs and mark revision active.

## Actionable Implementation Slices

1. Add provider plan dataclasses and normalized output objects.
2. Add dry-run OCI plan adapter for core node groups.
3. Add dry-run Linode and DigitalOcean sketch plan adapters.
4. Add Terraform input renderer for provider plans.
5. Add Ansible inventory/runbook renderer with management paths.
6. Add provider error classification types and tests.
7. Add OCI capacity and Ubuntu package-health runbook models.
8. Add deployment orchestrator plan-only job flow.

## Non-Mutation Rule

Until an explicit future work item authorizes live provider execution, all provider adapters must run in dry-run, render-only, or plan-only mode.
