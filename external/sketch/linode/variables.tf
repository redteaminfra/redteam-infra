variable "middle_region" {}
variable "edge_regions" {}
variable "linode_image" {}
variable "linode_api_token" {}
variable "engagement_name" {}
variable "ssh_private_key" {}
variable "ssh_public_key" {}

variable "allowed_tcp_ports" {
  default = ["22", "80", "443", "2222"]
}

variable "ssh_config_path" {
  default = "~/.ssh"
}

# See https://registry.terraform.io/providers/linode/linode/latest/docs/data-sources/instance_types
# for determining types
variable "edge_type" {
  default = "g6-nanode-1"
}

# See https://registry.terraform.io/providers/linode/linode/latest/docs/data-sources/instance_types
# for determining types
variable "middle_type" {
  default = "g6-nanode-1"
}

variable "middle_count" {
  default = 1
}

variable "edge_count_per_region" {
  default = 1
}
