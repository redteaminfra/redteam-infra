provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.oci_api_fingerprint
  private_key_path = var.oci_api_private_key_path
  region           = var.region
}

# this is basically a workaround for
# https://github.com/hashicorp/terraform/issues/14343
locals {
}

module "op" {
  source = "./modules/rti"

  region = var.region

  instance_user = var.instance_user
  homebase_user = var.homebase_user

  op_name        = var.op_name
  avail_dom      = var.avail_dom
  compartment_id = var.compartment_id

  vcn_cidr_block = var.vcn_cidr_block

  ssh_provisioning_public_key  = var.ssh_provisioning_public_key
  ssh_provisioning_private_key = var.ssh_provisioning_private_key

  infra_subnet_cidr = var.infra_subnet_cidr
  infra_shape       = var.infra_shape

  proxy_shape = var.proxy_shape
  proxy_name  = var.proxy_name

  provisioners_dir = var.provisioners_dir
}
