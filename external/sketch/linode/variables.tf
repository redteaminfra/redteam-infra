# Copyright (c) 2026, Oracle and/or its affiliates.
variable "middle_region" {}
variable "edge_regions" {
  type = list(string)
}
variable "linode_image" {}
variable "linode_api_token" {}
variable "engagement_name" {}

variable "allowed_tcp_ports" {
  description = "List of TCP ports to allow access to. This will be used to create the firewall rules."
  type        = list(string)
  default     = ["22", "80", "443", "2222"]
}

variable "ssh_pub_key_path" {
  description = "Path to the public key to be used for SSH access to the Linodes."
  default     = ""
}

variable "ssh_priv_key_path" {
  description = "Path to the private key to be used for SSH access to the Linodes."
  default     = ""
}

variable "ssh_config_path" {
  description = "Path to the SSH config directory. This is where the SSH config file will be written."
  default     = "~/.ssh"
}

# See https://registry.terraform.io/providers/linode/linode/latest/docs/data-sources/instance_types
# for determining types
variable "edge_type" {
  description = "Linode type to use for the edge nodes. Other options can be found at: https://www.linode.com/docs/api/linode-types/"
  default     = "g6-nanode-1"
}

# See https://registry.terraform.io/providers/linode/linode/latest/docs/data-sources/instance_types
# for determining types
variable "middle_type" {
  description = "Linode type to use for the middle nodes. Other options can be found at: https://www.linode.com/docs/api/linode-types/"
  default     = "g6-nanode-1"
}

variable "middle_count" {
  description = "How many middle nodes to create."
  default     = 1
  type        = number

  validation {
    condition     = var.middle_count >= 0 && floor(var.middle_count) == var.middle_count
    error_message = "middle_count must be a non-negative whole number."
  }
}

variable "edge_count_per_region" {
  description = "How many edge nodes to create per region."
  default     = 1
  type        = number

  validation {
    condition     = var.edge_count_per_region >= 0 && floor(var.edge_count_per_region) == var.edge_count_per_region
    error_message = "edge_count_per_region must be a non-negative whole number."
  }
}
