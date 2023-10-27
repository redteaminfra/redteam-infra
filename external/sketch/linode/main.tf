locals {
  abs_ssh_config_path  = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
  default_ssh_priv_key = pathexpand("~/.ssh/${var.engagement_name}")
  default_ssh_pub_key  = pathexpand("~/.ssh/${var.engagement_name}.pub")
  ssh_priv_key_path    = length(var.ssh_priv_key_path) > 0 ? var.ssh_priv_key_path : local.default_ssh_priv_key
  ssh_pub_key_path     = length(var.ssh_pub_key_path) > 0 ? var.ssh_pub_key_path : local.default_ssh_pub_key
}
