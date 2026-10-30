# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "digitalocean" {}
mock_provider "local" {}

variables {
  middles = {
    primary   = { region = "nyc3", ordinal = 1 }
    secondary = { region = "sfo3", ordinal = 2 }
  }
  edge_groups = {
    nyc = { region = "nyc3", middle_node = "primary", count = 1 }
    sfo = { region = "sfo3", middle_node = "secondary", count = 2 }
    sfo_extra = { region = "sfo3", middle_node = "primary", ordinals = [3] }
  }
  docean_image     = "ubuntu-22-04-x64"
  do_pat           = "mock-token"
  engagement_name  = "keyed-test"
  ssh_pub_key_path = "tests/fixtures/id_ed25519.pub"
}

run "keyed_regions_and_parent_middles" {
  command = plan

  assert {
    condition     = toset(keys(digitalocean_droplet.middle)) == toset(["primary", "secondary"])
    error_message = "Middle names must be stable Terraform addresses."
  }

  assert {
    condition     = toset(keys(digitalocean_droplet.edge)) == toset(["nyc3-01", "sfo3-01", "sfo3-02", "sfo3-03"])
    error_message = "Edge addresses must use provider region and regional ordinal across groups."
  }

  assert {
    condition     = output.edge_nodes["sfo3-03"].middle_node == "primary" && output.edge_nodes["sfo3-02"].middle_node == "secondary"
    error_message = "Each edge must retain its selected middle node."
  }
}

run "selected_retirement_keeps_other_addresses" {
  command = plan

  variables {
    edge_groups = {
      sfo = { region = "sfo3", middle_node = "secondary", ordinals = [1, 3] }
    }
  }

  assert {
    condition     = toset(keys(digitalocean_droplet.edge)) == toset(["sfo3-01", "sfo3-03"])
    error_message = "Explicit ordinals must retain nodes around a selected retirement."
  }
}

run "legacy_edge_only_remains_available" {
  command = plan

  variables {
    middles               = null
    edge_groups           = null
    middle_count          = 0
    edge_regions          = ["sfo3"]
    edge_count_per_region = 2
  }

  assert {
    condition     = length(digitalocean_droplet.middle) == 0 && toset(keys(digitalocean_droplet.edge)) == toset(["sfo3-01", "sfo3-02"])
    error_message = "Legacy edge-only roots must still create their requested edges."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Legacy edge-only roots must not produce full-chain artifacts."
  }
}

run "cross_provider_edge_only" {
  command = plan

  variables {
    middles               = {}
    edge_groups           = { sfo = { region = "sfo3", middle_node = "linode-primary", count = 1 } }
    external_middle_nodes = ["linode-primary"]
  }

  assert {
    condition     = length(digitalocean_droplet.middle) == 0 && output.edge_nodes["sfo3-01"].middle_node == "linode-primary"
    error_message = "A DigitalOcean edge must retain its external Linode parent name."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Barragan composes artifacts for cross-provider chains."
  }
}

run "local_and_cross_provider_edge_groups" {
  command = plan

  variables {
    edge_groups = {
      nyc = { region = "nyc3", middle_node = "primary", count = 1 }
      sfo = { region = "sfo3", middle_node = "linode-primary", count = 1 }
    }
    external_middle_nodes = ["linode-primary"]
  }

  assert {
    condition     = length(digitalocean_droplet.middle) == 2 && output.edge_nodes["sfo3-01"].middle_node == "linode-primary" && output.edge_nodes["nyc3-01"].middle_node == "primary"
    error_message = "Local and external parent identities must survive in edge outputs."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Mixed local/external parent references must defer artifacts to Barragan."
  }
}
