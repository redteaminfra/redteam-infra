variable "providers" {
  description = "List of providers to use"
  type = list(string)
  default = ["aws", "oci", "linode"]
}

module "aws_infra" {
  source = "./aws"
  count = contains(var.providers, "aws") ? 1 : 0
  # Add necessary variables
}

module "oci_infra" {
  source = "./oci"
  count = contains(var.providers, "oci") ? 1 : 0
  # Add necessary variables
}

module "linode_infra" {
  source = "./linode"
  count = contains(var.providers, "linode") ? 1 : 0
  # Add necessary variables
}

module "aws_sketch" {
  source = "./aws/sketch"
  count = contains(var.providers, "aws") ? 1 : 0
  # Add necessary variables
}

module "oci_sketch" {
  source = "./oci/sketch"
  count = contains(var.providers, "oci") ? 1 : 0
  # Add necessary variables
}

module "linode_sketch" {
  source = "./linode/sketch"
  count = contains(var.providers, "linode") ? 1 : 0
  # Add necessary variables
}

module "generate_inventory" {
  source = "./modules/generate_inventory"
  providers = var.providers
  aws_hosts = module.aws_infra.hosts
  oci_hosts = module.oci_infra.hosts
  linode_hosts = module.linode_infra.hosts
  # Add other necessary variables
}