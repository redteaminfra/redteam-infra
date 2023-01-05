# Copyright (c) 2022, Oracle and/or its affiliates.

variable "tenancy_ocid" {}
variable "user_ocid" {}
variable "compartment_id" {}
variable "ad_number" {}
variable "fingerprint" {}
variable "private_key_path" {}
variable "ssh_provisioning_private_key" {}
variable "ssh_provisioning_public_key" {}
variable "region" {}
variable "operation_name" {}
variable "homebase_shape" {}
variable "proxy_shape" {}
variable "elk_shape" {}


variable "image_username" {
  default = "ubuntu"
}

variable "proxy_count" {
  default = 1
}

variable "boot_volume_size_in_gbs" {
  default = 512
}

variable "preserve_boot_volume" {
  default = false
}

variable "network_protocol" {
  type    = map(string)
  default = {
    "tcp"  = "6"
    "icmp" = "1"
    "udp"  = "17"
  }
}

variable "vcn_cidr_block" {
  default = "192.168.0.0/16"
}

variable "subnet_cidr_blocks" {
  type    = map(string)
  default = {
    "infra"   = "192.168.0.0/24"
    "utility" = "192.168.1.0/24"
    "proxy"   = "192.168.2.0/24"
  }
}

variable "ssh_allowed_cidr_ranges" {
  type = set(string)
}