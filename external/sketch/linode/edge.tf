resource "linode_instance" "edge" {
                  # edge-region-number
  label           = "edge-${var.engagement_name}-${element(var.edge_regions, floor(count.index / var.edge_count_per_region))}-${format("%02g", (count.index % var.edge_count_per_region) + 1)}"
  region          = element(var.edge_regions, floor(count.index / var.edge_count_per_region))
  count           = var.edge_count_per_region * length(var.edge_regions)
  type            = var.edge_type
  image           = var.linode_image
  tags            = [var.engagement_name]
  root_pass       = random_password.root_password.result
  authorized_keys = [local.ssh_public_key_content]
}