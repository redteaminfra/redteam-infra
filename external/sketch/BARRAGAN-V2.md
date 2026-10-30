# Barragan keyed-provider v2 pin

The ordinary `digitalocean/` and `linode/` directories remain the editable
Redteam-infra roots. Their `providers.tf` files and normal `terraform init`
behavior are unchanged.

Barragan's opt-in keyed-provider v2 workspace copies a provider root, then
replaces its `providers.tf` with that provider's `barragan-v2/providers.tf` and
copies `barragan-v2/.terraform.lock.hcl` to the workspace root. Do not copy the
sidecar directory into a Terraform root alongside the original `providers.tf`:
two provider declarations would conflict. Barragan must verify the selected
sidecar and lockfile content, run `terraform init -lockfile=readonly`, and
retain the same lock for plan and saved-plan apply. A provider upgrade is an
explicit reviewed change to the sidecar and its lockfile, followed by plan
schema and disposable deployment tests.
