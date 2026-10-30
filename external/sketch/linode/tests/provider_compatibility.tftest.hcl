# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "linode" {}
mock_provider "random" {}
mock_provider "local" {}

variables {
  middle_region         = "us-sea"
  edge_regions          = ["us-sea", "us-east"]
  linode_image          = "linode/ubuntu22.04"
  linode_api_token      = "mock-token"
  engagement_name       = "provider-compat"
  ssh_pub_key_path      = "tests/fixtures/id_ed25519.pub"
  ssh_priv_key_path     = "tests/fixtures/id_ed25519"
  middle_count          = 1
  edge_count_per_region = 1
}

run "full_chain_preserves_local_artifacts" {
  command = plan

  assert {
    condition     = join(",", local.edge_output_order) == "us-sea-01,us-east-01"
    error_message = "Legacy list outputs must retain the input edge_regions order."
  }

  assert {
    condition     = length(linode_instance.middle) == 1 && length(linode_instance.edge) == 2
    error_message = "The typed multi-region input must create one middle and one edge per region."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 1 && length(local_file.ansible_inventory) == 1
    error_message = "A full chain must retain its local SSH and Ansible artifacts."
  }

  assert {
    condition     = length(output.middle_public_ips) == 1 && length(output.edge_public_ips) == 2
    error_message = "Full-chain component outputs must describe every planned node."
  }

  assert {
    condition     = alltrue([for rule in linode_firewall.firewall.inbound : contains(["TCP", "UDP", "ICMP"], rule.protocol)])
    error_message = "Linode firewall rules must use provider-compatible uppercase protocols."
  }

  assert {
    condition     = alltrue([for rule in linode_firewall.firewall.outbound : contains(["TCP", "UDP", "ICMP"], rule.protocol)])
    error_message = "Linode outbound firewall rules must use provider-compatible uppercase protocols."
  }

  assert {
    condition = alltrue([
      for rule in concat(linode_firewall.firewall.inbound, linode_firewall.firewall.outbound) :
      rule.label == lower(rule.label)
    ])
    error_message = "Linode firewall labels must remain lowercase and operator-readable."
  }
}

run "middle_only_skips_full_chain_artifacts" {
  command = plan

  variables {
    edge_regions = []
  }

  assert {
    condition     = length(linode_instance.middle) == 1 && length(linode_instance.edge) == 0
    error_message = "Middle-only mode must not create edge nodes."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Middle-only mode must skip artifacts that require both component roles."
  }

  assert {
    condition     = length(output.middle_public_ips) == 1 && length(output.edge_public_ips) == 0
    error_message = "Middle-only outputs must remain safe for a composing caller."
  }
}

run "edge_only_skips_full_chain_artifacts" {
  command = plan

  variables {
    middle_count = 0
  }

  assert {
    condition     = length(linode_instance.middle) == 0 && length(linode_instance.edge) == 2
    error_message = "Edge-only mode must create only the requested regional edge nodes."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Edge-only mode must skip artifacts that require both component roles."
  }

  assert {
    condition     = length(output.middle_instance_ids) == 0 && length(output.edge_instance_ids) == 2
    error_message = "Edge-only instance ID outputs must remain safe for a composing caller."
  }
}

run "counts_must_be_non_negative_whole_numbers" {
  command = plan

  variables {
    middle_count = -1
  }

  expect_failures = [var.middle_count]
}
