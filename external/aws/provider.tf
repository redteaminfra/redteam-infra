terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }
  }
}

provider "aws" {
  shared_config_files = [ "~/.aws/config" ]
  shared_credentials_files = [ var.shared_credentials_file ]
  profile = "default"
}

provider "local" {}