# Copyright (c) 2026, Oracle and/or its affiliates.
resource "linode_instance" "middle" {
  label           = "middle${format("%02g", each.value.ordinal)}-${var.engagement_name}"
  region          = each.value.region
  for_each        = local.middle_nodes
  type            = var.middle_type
  image           = var.linode_image
  tags            = [var.engagement_name]
  root_pass       = random_password.root_password.result
  authorized_keys = [chomp(file(local.ssh_pub_key_path))]
}
