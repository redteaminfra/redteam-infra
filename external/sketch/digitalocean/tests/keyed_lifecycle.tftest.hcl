# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "digitalocean" {
  mock_resource "digitalocean_droplet" {
    # Firewall droplet_ids accepts numeric IDs; the default mock ID is text.
    defaults = { id = "123456" }
  }
}
mock_provider "local" {}

variables {
  middles = {
    primary = { region = "nyc3", ordinal = 1 }
  }
  edge_groups = {
    sfo = { region = "sfo3", middle_node = "primary", count = 3 }
    nyc = { region = "nyc3", middle_node = "primary", count = 1 }
  }
  docean_image     = "ubuntu-22-04-x64"
  do_pat           = "mock-token"
  engagement_name  = "lifecycle-test"
  ssh_pub_key_path = "tests/fixtures/id_ed25519.pub"
}

run "initial" {
  command = apply

  assert {
    condition     = toset(keys(output.edge_nodes)) == toset(["nyc3-01", "sfo3-01", "sfo3-02", "sfo3-03"])
    error_message = "Initial regional edges must have stable addresses."
  }
}

run "append_sfo_edge" {
  command = apply

  variables {
    edge_groups = {
      sfo = { region = "sfo3", middle_node = "primary", count = 4 }
      nyc = { region = "nyc3", middle_node = "primary", count = 1 }
    }
  }

  assert {
    condition = alltrue([
      for name in ["nyc3-01", "sfo3-01", "sfo3-02", "sfo3-03"] :
      output.edge_nodes[name].id == run.initial.edge_nodes[name].id
    ]) && contains(keys(output.edge_nodes), "sfo3-04")
    error_message = "Appending an edge must retain every existing provider node."
  }
}

run "retire_sfo_02" {
  command = apply

  variables {
    edge_groups = {
      sfo = { region = "sfo3", middle_node = "primary", ordinals = [1, 3, 4] }
      nyc = { region = "nyc3", middle_node = "primary", count = 1 }
    }
  }

  assert {
    condition = !contains(keys(output.edge_nodes), "sfo3-02") && alltrue([
      for name in ["nyc3-01", "sfo3-01", "sfo3-03", "sfo3-04"] :
      output.edge_nodes[name].id == run.append_sfo_edge.edge_nodes[name].id
    ])
    error_message = "Selected retirement must remove only sfo3-02."
  }
}

run "reorder_groups" {
  command = plan

  variables {
    edge_groups = {
      nyc = { region = "nyc3", middle_node = "primary", count = 1 }
      sfo = { region = "sfo3", middle_node = "primary", ordinals = [1, 3, 4] }
    }
  }

  assert {
    condition = alltrue([
      for name in ["nyc3-01", "sfo3-01", "sfo3-03", "sfo3-04"] :
      output.edge_nodes[name].id == run.retire_sfo_02.edge_nodes[name].id
    ])
    error_message = "Reordering groups must not replace retained nodes."
  }
}
