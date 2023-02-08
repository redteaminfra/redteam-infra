locals {
  ssh_public_key_content = chomp(file(var.ssh_public_key))
  abs_ssh_config_path = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
}