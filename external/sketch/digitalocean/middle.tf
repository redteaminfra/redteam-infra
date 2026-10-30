# Copyright (c) 2026, Oracle and/or its affiliates.
resource "digitalocean_droplet" "middle" {
  name     = "middle${format("%02g", each.value.ordinal)}-${var.engagement_name}"
  region   = each.value.region
  for_each = local.middle_nodes
  size     = var.middle_size
  image    = var.docean_image
  tags     = var.firewall_selector_tag == null ? [var.engagement_name] : [var.firewall_selector_tag]
  ssh_keys = [digitalocean_ssh_key.key.id]
}
