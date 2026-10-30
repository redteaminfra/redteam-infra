# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "linode" {}
mock_provider "random" {}
mock_provider "local" {}

variables {
  middle_region         = "us-sea"
  edge_regions          = ["us-sea"]
  linode_image          = "linode/ubuntu22.04"
  linode_api_token      = "mock-token"
  engagement_name       = "udp-input"
  ssh_pub_key_path      = "tests/fixtures/id_ed25519.pub"
  ssh_priv_key_path     = "tests/fixtures/id_ed25519"
  middle_count          = 1
  edge_count_per_region = 1
}

run "default_keeps_public_udp_closed_and_tcp_unchanged" {
  command = plan

  assert {
    condition = length([
      for rule in linode_firewall.firewall.inbound : rule
      if can(regex("^allow-udp-[0-9]", rule.label))
    ]) == 0
    error_message = "The default must not add public UDP ingress."
  }

  assert {
    condition = length([
      for rule in linode_firewall.firewall.inbound : rule
      if rule.label == "allow-tcp-22" && rule.protocol == "TCP" && rule.ports == "22"
    ]) == 1
    error_message = "The legacy public TCP/22 default must remain unchanged."
  }
}

run "selected_udp_ports_do_not_change_trusted_ssh_or_tcp" {
  command = plan

  variables {
    trusted_ssh_cidrs = ["198.51.100.10/32"]
    allowed_udp_ports = ["53", "3478"]
  }

  assert {
    condition = length([
      for rule in linode_firewall.firewall.inbound : rule
      if can(regex("^allow-udp-[0-9]", rule.label)) && rule.protocol == "UDP" && contains(["53", "3478"], rule.ports)
    ]) == 2
    error_message = "Only the selected UDP ports may be added."
  }

  assert {
    condition = length([
      for rule in linode_firewall.firewall.inbound : rule
      if rule.label == "allow-tcp-22-trusted" && rule.protocol == "TCP" && rule.ports == "22"
      ]) == 1 && length([
      for rule in linode_firewall.firewall.inbound : rule
      if rule.label == "allow-tcp-22"
    ]) == 0
    error_message = "UDP opt-in must not broaden trusted management SSH."
  }

  assert {
    condition = length([
      for rule in linode_firewall.firewall.inbound : rule
      if contains(["allow-tcp-80", "allow-tcp-443", "allow-tcp-2222"], rule.label) && rule.protocol == "TCP"
    ]) == 3
    error_message = "UDP opt-in must preserve the standard public TCP ports."
  }
}
