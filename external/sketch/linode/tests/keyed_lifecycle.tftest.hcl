# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "linode" {
  mock_resource "linode_instance" {
    defaults = {
      id         = "123456"
      ip_address = "198.51.100.10"
      ipv4       = ["198.51.100.10"]
    }
  }
}
mock_provider "random" {
  mock_resource "random_password" {
    # Linode validates password length even with a mocked provider.
    defaults = { result = "ValidTestPassword123!" }
  }
}
mock_provider "local" {}

variables {
  middles = {
    primary = { region = "us-east", ordinal = 1 }
  }
  edge_groups = {
    sea  = { region = "us-sea", middle_node = "primary", count = 3 }
    east = { region = "us-east", middle_node = "primary", count = 1 }
  }
  linode_image     = "linode/ubuntu22.04"
  linode_api_token = "mock-token"
  engagement_name  = "lifecycle-test"
  ssh_pub_key_path = "tests/fixtures/id_ed25519.pub"
}

run "initial" {
  command = apply

  assert {
    condition     = toset(keys(output.edge_nodes)) == toset(["us-east-01", "us-sea-01", "us-sea-02", "us-sea-03"])
    error_message = "Initial regional edges must have stable addresses."
  }
}

run "append_sea_edge" {
  command = apply

  variables {
    edge_groups = {
      sea  = { region = "us-sea", middle_node = "primary", count = 4 }
      east = { region = "us-east", middle_node = "primary", count = 1 }
    }
  }

  assert {
    condition = alltrue([
      for name in ["us-east-01", "us-sea-01", "us-sea-02", "us-sea-03"] :
      output.edge_nodes[name].id == run.initial.edge_nodes[name].id
    ]) && contains(keys(output.edge_nodes), "us-sea-04")
    error_message = "Appending an edge must retain every existing provider node."
  }
}

run "retire_sea_02" {
  command = apply

  variables {
    edge_groups = {
      sea  = { region = "us-sea", middle_node = "primary", ordinals = [1, 3, 4] }
      east = { region = "us-east", middle_node = "primary", count = 1 }
    }
  }

  assert {
    condition = !contains(keys(output.edge_nodes), "us-sea-02") && alltrue([
      for name in ["us-east-01", "us-sea-01", "us-sea-03", "us-sea-04"] :
      output.edge_nodes[name].id == run.append_sea_edge.edge_nodes[name].id
    ])
    error_message = "Selected retirement must remove only us-sea-02."
  }
}

run "reorder_groups" {
  command = plan

  variables {
    edge_groups = {
      east = { region = "us-east", middle_node = "primary", count = 1 }
      sea  = { region = "us-sea", middle_node = "primary", ordinals = [1, 3, 4] }
    }
  }

  assert {
    condition = alltrue([
      for name in ["us-east-01", "us-sea-01", "us-sea-03", "us-sea-04"] :
      output.edge_nodes[name].id == run.retire_sea_02.edge_nodes[name].id
    ])
    error_message = "Reordering groups must not replace retained nodes."
  }
}
