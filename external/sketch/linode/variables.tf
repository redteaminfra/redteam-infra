# Copyright (c) 2026, Oracle and/or its affiliates.
variable "middle_region" {
  description = "Legacy middle region; use middles for new deployments."
  default     = null
}
variable "edge_regions" {
  description = "Legacy edge regions; use edge_groups for new deployments."
  type        = list(string)
  default     = []
}
variable "middles" {
  description = "Middle nodes addressed by stable logical names."
  type = map(object({
    region  = string
    ordinal = number
  }))
  default = null

  validation {
    condition = var.middles == null ? true : alltrue([
      for node in values(var.middles) : node.ordinal > 0 && floor(node.ordinal) == node.ordinal && length(trimspace(node.region)) > 0
    ]) && length(distinct([for node in values(var.middles) : node.ordinal])) == length(var.middles)
    error_message = "Each middle needs a nonempty region and a unique positive whole-number ordinal."
  }
}
variable "external_middle_nodes" {
  description = "Logical middle names managed in another provider root; use only for cross-provider edge groups."
  type        = set(string)
  default     = []

  validation {
    condition     = alltrue([for name in var.external_middle_nodes : length(trimspace(name)) > 0])
    error_message = "external_middle_nodes cannot contain an empty name."
  }
}
variable "edge_groups" {
  description = "Regional allocations. Set count (and optionally ordinal_start), or set explicit ordinals; middle_node names an entry in middles."
  type = map(object({
    region        = string
    middle_node   = string
    count         = optional(number)
    ordinal_start = optional(number, 1)
    ordinals      = optional(list(number))
  }))
  default = null

  validation {
    condition = var.edge_groups == null ? true : alltrue([
      for group in values(var.edge_groups) :
      length(trimspace(group.region)) > 0 &&
      ((group.count == null) != (group.ordinals == null)) &&
      (group.count == null ? true : group.count >= 0 && floor(group.count) == group.count) &&
      group.ordinal_start > 0 && floor(group.ordinal_start) == group.ordinal_start &&
      (group.ordinals == null ? true : alltrue([for ordinal in group.ordinals : ordinal > 0 && floor(ordinal) == ordinal]) && length(distinct(group.ordinals)) == length(group.ordinals))
    ])
    error_message = "Each edge group needs a region and exactly one of count or ordinals; ordinals must be unique positive whole numbers."
  }
}
variable "linode_image" {}
variable "linode_api_token" {}
variable "engagement_name" {}

variable "allowed_tcp_ports" {
  description = "List of TCP ports to allow access to. This will be used to create the firewall rules."
  type        = list(string)
  default     = ["22", "80", "443", "2222"]
}

variable "allowed_udp_ports" {
  description = "Optional UDP ports to allow at the provider firewall."
  type        = list(string)
  default     = []
}

variable "trusted_ssh_cidrs" {
  description = "Optional trusted IPv4 /32 source addresses for TCP/22. Null preserves the legacy public SSH rule."
  type        = list(string)
  default     = null

  validation {
    condition = var.trusted_ssh_cidrs == null ? true : (
      length(var.trusted_ssh_cidrs) > 0 && alltrue([
        for cidr in var.trusted_ssh_cidrs :
        cidr == trimspace(cidr) && can(cidrnetmask(cidr)) && endswith(cidr, "/32")
      ])
    )
    error_message = "trusted_ssh_cidrs must be a nonempty list of valid IPv4 /32 source addresses."
  }
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
