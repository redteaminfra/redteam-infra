# DigitalOcean sketch infrastructure

Copy `variables.tfvars.example` to `variables.tfvars`, then edit the file. Supply a DigitalOcean personal access token, an engagement name, the image used by your engagement, and the SSH paths if they differ from the defaults. Use the same normal file-editing workflow for later topology changes.

From this directory:

```sh
terraform init
terraform plan -var-file=variables.tfvars
terraform apply -var-file=variables.tfvars
terraform output run-ansible
```

Run the `run-ansible` command printed by Terraform after the hosts are ready. The module writes `inventory.ini` and the engagement sketch SSH file when both middle and edge nodes exist. Inspect those files before Ansible or SSH. The normal proxy and homebase must already be available.

## Edit the topology

`middles` names each middle node and gives it a provider region and an engagement-wide ordinal. Each `edge_groups` entry requests edges in one concrete DigitalOcean region. `middle_node` names the middle through which those edges are reached. The group label is for organizing the tfvars file; it is not part of an edge's Terraform address.

```hcl
middles = {
  primary   = { region = "nyc3", ordinal = 1 }
  secondary = { region = "sfo3", ordinal = 2 }
}

edge_groups = {
  new_york      = { region = "nyc3", middle_node = "primary", count = 1 }
  san_francisco = { region = "sfo3", middle_node = "secondary", count = 2 }
  san_francisco_extra = {
    region        = "sfo3"
    middle_node   = "primary"
    count         = 1
    ordinal_start = 3
  }
}
```

The edges above have stable addresses `nyc3-01`, `sfo3-01`, `sfo3-02`, and `sfo3-03`. Their hostnames keep the existing `edge-<engagement>-<region>-<ordinal>` form. Two groups in the same region must use distinct ordinals. Terraform rejects duplicate addresses and unknown middle names. Reordering groups or map entries does not change resource addresses.

To retire `sfo3-02` while retaining `sfo3-01`, replace that group's `count = 2` with `ordinals = [1]`; keep the other group at ordinal `03`. To add a new edge later, set `ordinals = [1, 4]`. Explicit ordinals let you select the removed node and avoid reusing its number. Exactly one of `count` or `ordinals` is required per group. An edit to a node's image or region can still replace it, so always read the plan before applying.

Keep using explicit `ordinals` for that group after a retirement. Switching it back to `count` can allocate the retired number again. Terraform has no separate tombstone record in a hand-edited tfvars file.

For a mixed-provider chain, set `external_middle_nodes = ["linode-primary"]` and use that name in an edge group's `middle_node`. Every parent name must be local or explicitly declared external. This provider root still returns its node outputs, but it skips local SSH and inventory artifacts when any edge uses an external middle. Barragan combines the chain artifacts across providers.

The existing `middle_region`, `middle_count`, `edge_regions`, and `edge_count_per_region` input form is accepted for **fresh** Terraform states. Do not combine it with `middles` or `edge_groups`. Existing automation can still use middle-only or edge-only legacy roots; those partial modes omit local SSH and inventory files.

## Optional public SSH restriction for new roots

For a fresh disposable root, set `trusted_ssh_cidrs = ["<verified-jump-ip>/32"]` to replace the public TCP/22 rule with one rule limited to those IPv4 hosts. Omitting it preserves the existing public TCP/22 behavior. This pilot accepts individual `/32` sources only; wider network ranges need separate review. `allowed_tcp_ports` must still include `22`; omitting it or adding a public range such as `20-23` is rejected when the restriction is set. Other public ports remain as configured, including TCP/2222 and any UDP ports. The existing engagement-peer rule still admits traffic from the root's node IPs, including SSH; per-node host policy must enforce finer access. This is an opt-in policy for new roots, not an active-state migration. Review the plan before applying; do not change an active engagement's SSH access as part of a keyed-address migration.

## Barragan v2 firewall overlay

For a fresh Barragan-owned provider root, replace the rendered `firewall.tf` with `barragan-v2/firewall.tf` before Terraform init and plan. Do not place both files in the same Terraform root. This overlay retains the normal IPv4 rules, selector behavior, and resource address, but omits the legacy `::/0` inbound and outbound entries. DigitalOcean firewall rules are allows; the legacy comments calling those entries IPv6 blocks are incorrect. With no IPv6 allow rules in this firewall, its default deny behavior applies to IPv6. The manual root remains unchanged, and this overlay is not an active-state migration. Review the exact rendered plan and verify firewall attachment before relying on the policy.

## Existing count-addressed state

Changing this module does not automatically migrate state. For an existing deployment, preserve a state backup and map every old resource index to its stable new address before applying. For example, after writing a matching keyed tfvars file:

```sh
terraform state pull > state-before-keyed-migration.json
terraform state list
terraform state mv 'digitalocean_droplet.middle[0]' 'digitalocean_droplet.middle["primary"]'
terraform state mv 'digitalocean_droplet.edge[0]' 'digitalocean_droplet.edge["sfo3-01"]'
terraform plan -var-file=variables.tfvars
```

Those `state mv` lines are examples, not a complete migration. Repeat them for every middle and edge using the actual old index, region, and ordinal; keep the existing provider objects and singleton SSH key/firewall in state. The plan must show no unintended node replacement or deletion before any apply. Do not perform this procedure on an active engagement without its operator's migration review.

For a disposable deployment, destroy it through the same Terraform root and tfvars file and verify the DigitalOcean resources are gone.
