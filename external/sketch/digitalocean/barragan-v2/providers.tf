# Copyright (c) 2026, Oracle and/or its affiliates.
terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "2.103.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "2.9.1"
    }
  }
}

provider "digitalocean" {
  token = var.do_pat
}

resource "digitalocean_ssh_key" "key" {
  name       = "do-key"
  public_key = chomp(file(local.ssh_pub_key_path))
}

provider "local" {}
