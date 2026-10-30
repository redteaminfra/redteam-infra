# Copyright (c) 2026, Oracle and/or its affiliates.
terraform {
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "4.5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.9.1"
    }
    local = {
      source  = "hashicorp/local"
      version = "2.9.1"
    }
  }
}

provider "linode" {
  token = var.linode_api_token
}

provider "random" {}

provider "local" {}
