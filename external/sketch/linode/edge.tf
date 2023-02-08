resource "linode_instance" "edge" {
  label           = "edge${format("%02g", count.index + 1)}-${var.engagement_name}"
  region          = var.edge_region
  count           = var.edge_count
  type            = var.edge_type
  image           = var.linode_image
  tags            = [var.engagement_name]
  root_pass       = random_password.root_password.result
  authorized_keys = [local.ssh_public_key_content]
}