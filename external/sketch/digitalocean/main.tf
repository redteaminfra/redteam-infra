# Copyright (c) 2026, Oracle and/or its affiliates.
locals {
  abs_ssh_config_path  = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
  default_ssh_priv_key = pathexpand("~/.ssh/${var.engagement_name}")
  default_ssh_pub_key  = pathexpand("~/.ssh/${var.engagement_name}.pub")
  ssh_priv_key_path    = length(var.ssh_priv_key_path) > 0 ? var.ssh_priv_key_path : local.default_ssh_priv_key
  ssh_pub_key_path     = length(var.ssh_pub_key_path) > 0 ? var.ssh_pub_key_path : local.default_ssh_pub_key

  keyed_topology = var.middles != null || var.edge_groups != null
  middle_nodes = local.keyed_topology ? (var.middles == null ? {} : var.middles) : {
    for index in range(var.middle_count) : format("middle-%02d", index + 1) => {
      region  = var.middle_region
      ordinal = index + 1
    }
  }
  effective_edge_groups = local.keyed_topology ? (var.edge_groups == null ? {} : var.edge_groups) : {
    for index, region in var.edge_regions : format("legacy-%02d", index + 1) => {
      region        = region
      middle_node   = "middle-01"
      count         = var.edge_count_per_region
      ordinal_start = 1
      ordinals      = null
    }
  }
  edge_allocations = flatten([
    for group in values(local.effective_edge_groups) : [
      for ordinal in(group.ordinals == null ? range(group.ordinal_start, group.ordinal_start + group.count) : group.ordinals) : {
        region      = group.region
        middle_node = group.middle_node
        ordinal     = ordinal
        identity    = "${lower(group.region)}-${format("%02d", ordinal)}"
      }
    ]
  ])
  edge_nodes = { for edge in local.edge_allocations : edge.identity => edge }
  uses_external_middle = local.keyed_topology && anytrue([
    for group in values(local.effective_edge_groups) : contains(var.external_middle_nodes, group.middle_node)
  ])
  edge_output_order = local.keyed_topology ? sort(keys(local.edge_nodes)) : flatten([
    for region in var.edge_regions : [for ordinal in range(1, var.edge_count_per_region + 1) : "${lower(region)}-${format("%02d", ordinal)}"]
  ])
}
