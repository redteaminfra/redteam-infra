variable "network_protocol" {
  default = {
    "tcp"  = "6"
    "icmp" = "1"
    "udp"  = "17"
  }
}

variable "avail_dom" {
  default = "0" //0 - AD1, 1 - AD2, 2 - AD3
}

variable "region" {
}

variable "compartment_id" {
}

// TODO: revisit the Image ID / Shape / Host names defaults so we don't burden the callers

variable "infra_shape" {
  default = "VM.Standard2.1"
}

variable "vcn_cidr_block" {
  default = "192.168.0.0/16"
}

variable "infra_subnet_cidr" {
  default = "192.168.0.0/24"
}

variable "utility_cidr" {
  default = "192.168.1.0/24"
}

variable "proxy_cidr" {
  default = "192.168.2.0/24"
}

variable "proxy_name" {
  default = "proxy"
}

variable "proxy_shape" {
  default = "VM.Standard2.1"
}

variable "ssh_provisioning_public_key" {
}

variable "ssh_provisioning_private_key" {
}

variable "instance_user" {
  default = "ubuntu"
}

variable "homebase_user" {
  default = "ubuntu"
}

variable "op_name" {
}

variable "preserve_boot_volume" {
  default = "false"
}

variable "provisioners_dir" {
  default = "provisioners"
}

variable "default_image_size_gbs" {
  default = "512"
}
