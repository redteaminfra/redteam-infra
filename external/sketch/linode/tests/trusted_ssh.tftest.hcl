# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "linode" {}
mock_provider "random" {}
mock_provider "local" {}

variables {
  middle_region         = "us-sea"
  edge_regions          = ["us-sea"]
  linode_image          = "linode/ubuntu22.04"
  linode_api_token      = "mock-token"
  engagement_name       = "trusted-ssh"
  ssh_pub_key_path      = "tests/fixtures/id_ed25519.pub"
  ssh_priv_key_path     = "tests/fixtures/id_ed25519"
  middle_count          = 1
  edge_count_per_region = 1
}

run "legacy_public_ssh_is_unchanged" {
  command = plan

  assert {
    condition     = length([for rule in linode_firewall.firewall.inbound : rule if rule.protocol == "TCP" && rule.ports == "22" && contains(rule.ipv4, "0.0.0.0/0")]) == 1
    error_message = "Unset trusted_ssh_cidrs must preserve the existing single public TCP/22 rule."
  }
}

run "trusted_ssh_is_not_public_or_duplicated" {
  command = plan

  variables {
    trusted_ssh_cidrs = ["198.51.100.10/32", "203.0.113.4/32"]
    allowed_tcp_ports = ["22", "80", "443", "2222", "22"]
  }

  assert {
    condition     = length([for rule in linode_firewall.firewall.inbound : rule if rule.protocol == "TCP" && rule.ports == "22"]) == 1
    error_message = "An opted-in firewall must have exactly one TCP/22 rule even when 22 is repeated."
  }

  assert {
    condition = alltrue([
      for rule in linode_firewall.firewall.inbound :
      rule.ports != "22" || (length(rule.ipv4) == 2 && length(setsubtract(toset(rule.ipv4), toset(["198.51.100.10/32", "203.0.113.4/32"]))) == 0)
    ])
    error_message = "TCP/22 must have only the trusted source CIDRs."
  }

  assert {
    condition     = length([for rule in linode_firewall.firewall.inbound : rule if rule.protocol == "TCP" && rule.ports == "80" && contains(rule.ipv4, "0.0.0.0/0")]) == 1
    error_message = "Other public TCP ports must be unchanged."
  }
}

run "missing_ssh_port_is_rejected" {
  command = plan

  variables {
    trusted_ssh_cidrs = ["198.51.100.10/32"]
    allowed_tcp_ports = ["80", "443"]
  }

  expect_failures = [linode_firewall.firewall]
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
  expect_failures = [linode_firewall.firewall]
}
