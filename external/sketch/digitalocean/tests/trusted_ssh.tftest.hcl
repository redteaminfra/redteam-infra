# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "digitalocean" {}
mock_provider "local" {}

variables {
  middle_region         = "sfo3"
  edge_regions          = ["sfo3"]
  docean_image          = "ubuntu-22-04-x64"
  do_pat                = "mock-token"
  engagement_name       = "trusted-ssh"
  ssh_pub_key_path      = "tests/fixtures/id_ed25519.pub"
  ssh_priv_key_path     = "tests/fixtures/id_ed25519"
  middle_count          = 1
  edge_count_per_region = 1
}

run "legacy_public_ssh_is_unchanged" {
  command = plan

  assert {
    condition     = length([for rule in digitalocean_firewall.firewall.inbound_rule : rule if rule.protocol == "tcp" && rule.port_range == "22" && contains(rule.source_addresses, "0.0.0.0/0")]) == 1
    error_message = "Unset trusted_ssh_cidrs must preserve the existing single public TCP/22 rule."
  }
}

run "trusted_ssh_is_not_public_or_duplicated" {
  command = plan

  variables {
    trusted_ssh_cidrs = ["198.51.100.10/32", "203.0.113.4/32"]
    allowed_tcp_ports = ["22", "80", "443", "2222", "22"]
    allowed_udp_ports = ["3478"]
  }

  assert {
    condition     = length([for rule in digitalocean_firewall.firewall.inbound_rule : rule if rule.protocol == "tcp" && rule.port_range == "22"]) == 1
    error_message = "An opted-in firewall must have exactly one TCP/22 rule even when 22 is repeated."
  }

  assert {
    condition = alltrue([
      for rule in digitalocean_firewall.firewall.inbound_rule :
      rule.port_range != "22" || (length(rule.source_addresses) == 2 && length(setsubtract(toset(rule.source_addresses), toset(["198.51.100.10/32", "203.0.113.4/32"]))) == 0)
    ])
    error_message = "TCP/22 must have only the trusted source CIDRs."
  }

  assert {
    condition     = length([for rule in digitalocean_firewall.firewall.inbound_rule : rule if rule.protocol == "tcp" && rule.port_range == "80" && contains(rule.source_addresses, "0.0.0.0/0")]) == 1
    error_message = "Other public TCP ports must be unchanged."
  }

  assert {
    condition     = length([for rule in digitalocean_firewall.firewall.inbound_rule : rule if rule.protocol == "udp" && rule.port_range == "3478" && contains(rule.source_addresses, "0.0.0.0/0")]) == 1
    error_message = "Public UDP ports must be unchanged."
  }
}

run "missing_ssh_port_is_rejected" {
  command = plan

  variables {
    trusted_ssh_cidrs = ["198.51.100.10/32"]
    allowed_tcp_ports = ["80", "443"]
  }

  expect_failures = [digitalocean_firewall.firewall]
}

run "world_cidr_rejected" {
  command = plan
  variables { trusted_ssh_cidrs = ["0.0.0.0/0"] }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "ipv6_cidr_rejected" {
  command = plan
  variables { trusted_ssh_cidrs = ["::/0"] }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "broad_cidr_rejected" {
  command = plan
  variables { trusted_ssh_cidrs = ["203.0.113.0/24"] }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "invalid_ipv4_cidr_rejected" {
  command = plan
  variables { trusted_ssh_cidrs = ["999.999.999.999/32"] }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "empty_cidrs_rejected" {
  command = plan
  variables { trusted_ssh_cidrs = [] }
  expect_failures = [var.trusted_ssh_cidrs]
}

run "public_port_range_covering_ssh_rejected" {
  command = plan
  variables {
    trusted_ssh_cidrs = ["198.51.100.10/32"]
    allowed_tcp_ports = ["20-23"]
  }
  expect_failures = [digitalocean_firewall.firewall]
}
