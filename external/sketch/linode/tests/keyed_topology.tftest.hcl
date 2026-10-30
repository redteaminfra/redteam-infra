# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "linode" {}
mock_provider "random" {}
mock_provider "local" {}

variables {
  middles = {
    primary   = { region = "us-east", ordinal = 1 }
    secondary = { region = "us-sea", ordinal = 2 }
  }
  edge_groups = {
    east = { region = "us-east", middle_node = "primary", count = 1 }
    sea = { region = "us-sea", middle_node = "secondary", count = 2 }
    sea_extra = { region = "us-sea", middle_node = "primary", ordinals = [3] }
  }
  linode_image     = "linode/ubuntu22.04"
  linode_api_token = "mock-token"
  engagement_name  = "keyed-test"
  ssh_pub_key_path = "tests/fixtures/id_ed25519.pub"
}

run "keyed_regions_and_parent_middles" {
  command = plan

  assert {
    condition     = toset(keys(linode_instance.middle)) == toset(["primary", "secondary"])
    error_message = "Middle names must be stable Terraform addresses."
  }

  assert {
    condition     = toset(keys(linode_instance.edge)) == toset(["us-east-01", "us-sea-01", "us-sea-02", "us-sea-03"])
    error_message = "Edge addresses must use provider region and regional ordinal across groups."
  }

  assert {
    condition     = output.edge_nodes["us-sea-03"].middle_node == "primary" && output.edge_nodes["us-sea-02"].middle_node == "secondary"
    error_message = "Each edge must retain its selected middle node."
  }
}

run "selected_retirement_keeps_other_addresses" {
  command = plan

  variables {
    edge_groups = {
      sea = { region = "us-sea", middle_node = "secondary", ordinals = [1, 3] }
    }
  }

  assert {
    condition     = toset(keys(linode_instance.edge)) == toset(["us-sea-01", "us-sea-03"])
    error_message = "Explicit ordinals must retain nodes around a selected retirement."
  }
}

run "legacy_edge_only_remains_available" {
  command = plan

  variables {
    middles               = null
    edge_groups           = null
    middle_count          = 0
    edge_regions          = ["us-sea"]
    edge_count_per_region = 2
  }

  assert {
    condition     = length(linode_instance.middle) == 0 && toset(keys(linode_instance.edge)) == toset(["us-sea-01", "us-sea-02"])
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
    edge_groups           = { sea = { region = "us-sea", middle_node = "digitalocean-primary", count = 1 } }
    external_middle_nodes = ["digitalocean-primary"]
  }

  assert {
    condition     = length(linode_instance.middle) == 0 && output.edge_nodes["us-sea-01"].middle_node == "digitalocean-primary"
    error_message = "A Linode edge must retain its external DigitalOcean parent name."
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
      east = { region = "us-east", middle_node = "primary", count = 1 }
      sea  = { region = "us-sea", middle_node = "digitalocean-primary", count = 1 }
    }
    external_middle_nodes = ["digitalocean-primary"]
  }

  assert {
    condition     = length(linode_instance.middle) == 2 && output.edge_nodes["us-sea-01"].middle_node == "digitalocean-primary" && output.edge_nodes["us-east-01"].middle_node == "primary"
    error_message = "Local and external parent identities must survive in edge outputs."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Mixed local/external parent references must defer artifacts to Barragan."
  }
}
