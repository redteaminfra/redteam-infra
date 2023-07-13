# Copyright (c) 2023, Oracle and/or its affiliates.

# get latest Ubuntu Linux 20.04 image
data "oci_core_images" "ubuntu-version" {
  compartment_id   = var.compartment_id
  operating_system = "Canonical Ubuntu"
  filter {
    name   = "display_name"
    values = ["^Canonical-Ubuntu-${var.ubuntu-version}-([\\.0-9-]+)$"]
    regex  = true
  }
}
