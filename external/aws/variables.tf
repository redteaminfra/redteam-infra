variable "homebase_shape" {}
variable "proxy_shape" {}
variable "elk_shape" {}
variable "profile" {}

variable "image_username" {
  default = "ubuntu"
}

variable "ssh_config_path" {
  default = "~/.ssh"
}

variable "boot_volume_size_in_gbs" {
  default = 512
}

variable "proxy_count" {
  default = 1
}

variable "region" {
  default = "us-west-2"
}

variable "availability_zone" {
  default = "us-west-2a"
}

variable "shared_credentials_file" {
  default = "~/.aws/credentials"
}

variable "key_name" {
  default = "~/.ssh/id_rsa"
}

variable "public_key" {
  default = "~/.ssh/id_rsa.pub"
  
}

variable "engagement_name" {
}

variable "vpc_cidr_block" {
  default = "192.168.0.0/16"
}

variable "ssh_allowed_cidr_ranges" {
  type = set(string)
}