# Linode sketch infrastructure

Copy `variables.tfvars.example` to `variables.tfvars`, then edit the file. Supply a Linode API token, an engagement name, the image used by your engagement, and the SSH paths if they differ from the defaults. Use the same normal file-editing workflow for later topology changes.

From this directory:

```sh
terraform init
terraform plan -var-file=variables.tfvars
terraform apply -var-file=variables.tfvars
terraform output run-ansible
```

Run the `run-ansible` command printed by Terraform after the hosts are ready. The module writes `inventory.ini` and the engagement sketch SSH file when both middle and edge nodes exist. Inspect those files before Ansible or SSH. The normal proxy and homebase must already be available.

## Edit the topology

`middles` names each middle node and gives it a provider region and an engagement-wide ordinal. Each `edge_groups` entry requests edges in one concrete Linode region. `middle_node` names the middle through which those edges are reached. The group label is for organizing the tfvars file; it is not part of an edge's Terraform address.

```hcl
middles = {
  primary   = { region = "us-east", ordinal = 1 }
  secondary = { region = "us-sea", ordinal = 2 }
}

edge_groups = {
  newark  = { region = "us-east", middle_node = "primary", count = 1 }
  seattle = { region = "us-sea", middle_node = "secondary", count = 2 }
  seattle_extra = {
    region        = "us-sea"
    middle_node   = "primary"
    count         = 1
    ordinal_start = 3
  }
}
```

The edges above have stable addresses `us-east-01`, `us-sea-01`, `us-sea-02`, and `us-sea-03`. Their labels keep the existing `edge-<engagement>-<region>-<ordinal>` form. Two groups in the same region must use distinct ordinals. Terraform rejects duplicate addresses and unknown middle names. Reordering groups or map entries does not change resource addresses.

To retire `us-sea-02` while retaining `us-sea-01`, replace that group's `count = 2` with `ordinals = [1]`; keep the other group at ordinal `03`. To add a new edge later, set `ordinals = [1, 4]`. Explicit ordinals let you select the removed node and avoid reusing its number. Exactly one of `count` or `ordinals` is required per group. An edit to a node's image or region can still replace it, so always read the plan before applying.

Keep using explicit `ordinals` for that group after a retirement. Switching it back to `count` can allocate the retired number again. Terraform has no separate tombstone record in a hand-edited tfvars file.

For a mixed-provider chain, set `external_middle_nodes = ["digitalocean-primary"]` and use that name in an edge group's `middle_node`. Every parent name must be local or explicitly declared external. This provider root still returns its node outputs, but it skips local SSH and inventory artifacts when any edge uses an external middle. Barragan combines the chain artifacts across providers.

The existing `middle_region`, `middle_count`, `edge_regions`, and `edge_count_per_region` input form is accepted for **fresh** Terraform states. Do not combine it with `middles` or `edge_groups`. Existing automation can still use middle-only or edge-only legacy roots; those partial modes omit local SSH and inventory files.

## Optional public SSH restriction for new roots

For a fresh disposable root, set `trusted_ssh_cidrs = ["<verified-jump-ip>/32"]` to replace the public TCP/22 rule with one rule limited to those IPv4 hosts. Omitting it preserves the existing public TCP/22 behavior. This pilot accepts individual `/32` sources only; wider network ranges need separate review. `allowed_tcp_ports` must still include `22`; omitting it or adding a public range such as `20-23` is rejected when the restriction is set. Other public ports remain as configured, including TCP/2222. The existing engagement-peer rule still admits traffic from the root's node IPs, including SSH; per-node host policy must enforce finer access. This is an opt-in policy for new roots, not an active-state migration. Review the plan before applying; do not change an active engagement's SSH access as part of a keyed-address migration.

`allowed_udp_ports` is optional and defaults to an empty list. Add a port such
as `"53"` only when an inbound UDP route needs it, and review the firewall
plan. The provider rule admits that port to all nodes in this root; per-node
host firewall rules must limit it to the selected route.

## Existing count-addressed state

Changing this module does not automatically migrate state. For an existing deployment, preserve a state backup and map every old resource index to its stable new address before applying. For example, after writing a matching keyed tfvars file:

```sh
terraform state pull > state-before-keyed-migration.json
terraform state list
terraform state mv 'linode_instance.middle[0]' 'linode_instance.middle["primary"]'
terraform state mv 'linode_instance.edge[0]' 'linode_instance.edge["us-sea-01"]'
terraform plan -var-file=variables.tfvars
```

Those `state mv` lines are examples, not a complete migration. Repeat them for every middle and edge using the actual old index, region, and ordinal; keep the existing provider objects and singleton root password/firewall in state. The plan must show no unintended node replacement or deletion before any apply. Do not perform this procedure on an active engagement without its operator's migration review.

For a disposable deployment, destroy it through the same Terraform root and tfvars file and verify the Linode resources are gone.
