# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "digitalocean" {}
mock_provider "local" {}

variables {
  middle_region         = "sfo3"
  edge_regions          = ["sfo3", "nyc3"]
  docean_image          = "ubuntu-22-04-x64"
  do_pat                = "mock-token"
  engagement_name       = "provider-compat"
  ssh_pub_key_path      = "tests/fixtures/id_ed25519.pub"
  ssh_priv_key_path     = "tests/fixtures/id_ed25519"
  middle_count          = 1
  edge_count_per_region = 1
}

run "full_chain_preserves_local_artifacts" {
  command = plan

  assert {
    condition     = join(",", local.edge_output_order) == "sfo3-01,nyc3-01"
    error_message = "Legacy list outputs must retain the input edge_regions order."
  }

  assert {
    condition     = length(digitalocean_droplet.middle) == 1 && length(digitalocean_droplet.edge) == 2
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
}

run "middle_only_skips_full_chain_artifacts" {
  command = plan

  variables {
    edge_regions = []
  }

  assert {
    condition     = length(digitalocean_droplet.middle) == 1 && length(digitalocean_droplet.edge) == 0
    error_message = "Middle-only mode must not create edge nodes."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Middle-only mode must skip artifacts that require both component roles."
  }

  assert {
    condition     = length(output.middle_instance_ids) == 1 && length(output.edge_instance_ids) == 0
    error_message = "Middle-only instance ID outputs must remain safe for a composing caller."
  }
}

run "edge_only_skips_full_chain_artifacts" {
  command = plan

  variables {
    middle_count = 0
  }

  assert {
    condition     = length(digitalocean_droplet.middle) == 0 && length(digitalocean_droplet.edge) == 2
    error_message = "Edge-only mode must create only the requested regional edge nodes."
  }

  assert {
    condition     = length(local_file.ssh_stanza) == 0 && length(local_file.ansible_inventory) == 0
    error_message = "Edge-only mode must skip artifacts that require both component roles."
  }

  assert {
    condition     = length(output.middle_public_ips) == 0 && length(output.edge_public_ips) == 2
    error_message = "Edge-only outputs must remain safe for a composing caller."
  }
}

run "counts_must_be_non_negative_whole_numbers" {
  command = plan

  variables {
    edge_count_per_region = 1.5
  }

  expect_failures = [var.edge_count_per_region]
}
