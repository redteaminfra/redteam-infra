# Copyright (c) 2026, Oracle and/or its affiliates.
resource "linode_instance" "edge" {
  # edge-region-number
  label           = "edge-${var.engagement_name}-${each.value.region}-${format("%02g", each.value.ordinal)}"
  region          = each.value.region
  for_each        = local.edge_nodes
  type            = var.edge_type
  image           = var.linode_image
  tags            = [var.engagement_name]
  root_pass       = random_password.root_password.result
  authorized_keys = [chomp(file(local.ssh_pub_key_path))]
}
