# Copyright (c) 2022, Oracle and/or its affiliates.

data "oci_identity_availability_domain" "ad" {
  compartment_id = var.compartment_id
  ad_number      = var.ad_number
}