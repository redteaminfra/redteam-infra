variable "middle_region" {}
variable "edge_regions" {}
variable "docean_image" {}
variable "do_pat" {}
variable "engagement_name" {}

variable "allowed_tcp_ports" {
  description = "List of TCP ports to allow access to. This will be used to create the firewall rules."
  default = ["22", "80", "443", "2222"]
}

variable "ssh_pub_key_path" {
  description = "Path to the public key to be used for SSH access to the Droplets."
  default = ""
}

variable "ssh_priv_key_path" {
  description = "Path to the private key to be used for SSH access to the Droplets."
  default = ""
}

variable "ssh_config_path" {
  description = "Path to the SSH config directory. This is where the SSH config file will be written."
  default = "~/.ssh"
}

# See https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/data-sources/sizes
# for determining sizes
variable "edge_size" {
  description = "Digital Ocean size to use for the edge nodes. Other options can be found at: https://slugs.do-api.dev/"
  default = "s-1vcpu-1gb"
}

# See https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/data-sources/sizes
# for determining types
variable "middle_size" {
  description = "Digital Ocean size to use for the middle nodes. Other options can be found at: https://slugs.do-api.dev/"
  default = "s-1vcpu-1gb"
}

variable "middle_count" {
  description = "How many middle nodes to create."
  default = 1
}

variable "edge_count_per_region" {
  description = "How many edge nodes to create per region."
  default = 1
}
