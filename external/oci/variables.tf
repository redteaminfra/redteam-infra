# Copyright (c) 2023, Oracle and/or its affiliates.

variable "compartment_id" {}
variable "ad_number" {}
variable "region" {}
variable "engagement_name" {}
variable "homebase_shape" {}
variable "proxy_shape" {}
variable "elk_shape" {}

variable "config_file_profile" {}

variable "ubuntu-version" {
  description = "The version of Ubuntu you would like to use. Use the version number."
  default = "22.04"
}

variable "is_production" {
  default = false
}

variable "ssh_config_path" {
  default = "~/.ssh"
}

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

variable "backup_compartment_id" {
  description = "The compartment ID where backups will be stored."
  default = ""
}
