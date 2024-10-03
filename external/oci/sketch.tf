module "oci_sketch" {
  source = "./modules/oci/sketch"
  providers = {
    oci = oci
  }
  engagement_name = var.engagement_name
  ssh_config_path = var.ssh_config_path
  # Add other necessary variables
}