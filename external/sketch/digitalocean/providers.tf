terraform {
  required_providers {
    digitalocean = {
      source = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

provider "digitalocean" {
  token = var.do_pat
}

resource "digitalocean_ssh_key" "key" {
  name = "do-key"
  public_key = chomp(file(local.ssh_pub_key_path))
}

provider "local" {}