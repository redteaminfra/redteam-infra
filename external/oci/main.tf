provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
  region           = var.region
}

locals {
  shapes = {
    small     = "VM.Standard2.1"
    flexSmall = "VM.Standard3.Flex"
    flexLarge = "VM.Standard.E4.Flex"
    flexArm   = "VM.Standard.A1.Flex"
    bmLarge   = "BM.Standard.E4.128"
    bmArm     = "BM.Standard.A1.160"
  }
}
