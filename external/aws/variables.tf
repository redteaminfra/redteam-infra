variable "instance_types" {
  type    = "map"
  default = {
    "dev" = "t3.nano"
    "prod" = "t3.large"
  }
}

variable "amis" {
  type = "map"
  default = {
    "ubuntu18.04" = "ami-0e3e4660d8725dd31"
    "kali 2018.3a" = "ami-0f95cde6ebe3f5ec3"
  }
}

variable "env" {
  default = "dev"
}

variable "profile" {
  default = "terraform"
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

variable "aws_key_name" {
}

variable "op_name" {
}

variable "subnet_cidr" {
  default = "192.168.0.0/16"
}
