# Copyright (c) 2026, Oracle and/or its affiliates.

variable "compartment_id" {}
variable "ad_number" {}
variable "region" {}
variable "engagement_name" {}
variable "homebase_shape" {}
variable "proxy_shape" {}
variable "elk_shape" {}

variable "production_homebase_shape" {
  type        = string
  description = "Bare-metal homebase shape used when is_production is true."
  default     = "BM.Standard3.64"
}

variable "homebase_ocpus" {
  type        = number
  description = "OCPUs assigned when the selected homebase shape is Flex."
  default     = null

  validation {
    condition     = var.homebase_ocpus == null ? true : var.homebase_ocpus > 0
    error_message = "homebase_ocpus must be greater than zero when provided."
  }
}

variable "homebase_memory_in_gbs" {
  type        = number
  description = "Memory in GiB assigned when the selected homebase shape is Flex."
  default     = null

  validation {
    condition     = var.homebase_memory_in_gbs == null ? true : var.homebase_memory_in_gbs > 0
    error_message = "homebase_memory_in_gbs must be greater than zero when provided."
  }
}

variable "proxy_ocpus" {
  type        = number
  description = "OCPUs assigned to each proxy when proxy_shape is Flex."
  default     = null

  validation {
    condition     = var.proxy_ocpus == null ? true : var.proxy_ocpus > 0
    error_message = "proxy_ocpus must be greater than zero when provided."
  }
}

variable "proxy_memory_in_gbs" {
  type        = number
  description = "Memory in GiB assigned to each proxy when proxy_shape is Flex."
  default     = null

  validation {
    condition     = var.proxy_memory_in_gbs == null ? true : var.proxy_memory_in_gbs > 0
    error_message = "proxy_memory_in_gbs must be greater than zero when provided."
  }
}

variable "elk_ocpus" {
  type        = number
  description = "OCPUs assigned when elk_shape is Flex."
  default     = null

  validation {
    condition     = var.elk_ocpus == null ? true : var.elk_ocpus > 0
    error_message = "elk_ocpus must be greater than zero when provided."
  }
}

variable "elk_memory_in_gbs" {
  type        = number
  description = "Memory in GiB assigned when elk_shape is Flex."
  default     = null

  validation {
    condition     = var.elk_memory_in_gbs == null ? true : var.elk_memory_in_gbs > 0
    error_message = "elk_memory_in_gbs must be greater than zero when provided."
  }
}

variable "config_file_profile" {}

variable "ubuntu-version" {
  description = "The version of Ubuntu you would like to use. Use the version number."
  default     = "22.04"
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
  type    = number
  default = 512

  validation {
    condition     = var.boot_volume_size_in_gbs >= 50
    error_message = "boot_volume_size_in_gbs must be at least 50 GiB."
  }
}

variable "preserve_boot_volume" {
  default = false
}

variable "network_protocol" {
  type = map(string)
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
  type = map(string)
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
  default     = ""
}
