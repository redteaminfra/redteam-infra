module "linode_infra" {
  source = "./modules/linode/infra"
  providers = {
    linode = linode
  }
  engagement_name = var.engagement_name
  ssh_config_path = var.ssh_config_path
  # Add other necessary variables
}

module "linode_sketch" {
  source = "./modules/linode/sketch"
  providers = {
    linode = linode
  }
  engagement_name = var.engagement_name
  ssh_config_path = var.ssh_config_path
  # Add other necessary variables
}