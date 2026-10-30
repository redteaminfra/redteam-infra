# Copyright (c) 2026, Oracle and/or its affiliates.
resource "digitalocean_droplet" "edge" {
  name     = "edge-${var.engagement_name}-${each.value.region}-${format("%02g", each.value.ordinal)}"
  region   = each.value.region
  for_each = local.edge_nodes
  size     = var.edge_size
  image    = var.docean_image
  tags     = var.firewall_selector_tag == null ? [var.engagement_name] : [var.firewall_selector_tag]
  ssh_keys = [digitalocean_ssh_key.key.id]
}
