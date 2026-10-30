# Copyright (c) 2026, Oracle and/or its affiliates.
resource "digitalocean_firewall" "firewall" {
  name        = "${var.engagement_name}-firewall"
  droplet_ids = var.firewall_selector_tag == null ? concat([for node in values(digitalocean_droplet.middle) : node.id], [for node in values(digitalocean_droplet.edge) : node.id]) : []
  tags        = var.firewall_selector_tag == null ? [var.engagement_name] : [var.firewall_selector_tag]
  lifecycle {
    precondition {
      condition = var.trusted_ssh_cidrs == null ? true : contains(var.allowed_tcp_ports, "22") && alltrue([
        for port in var.allowed_tcp_ports : port == "22" || (
          can(regex("^[0-9]+$", port)) ? tonumber(port) != 22 : (
            can(regex("^[0-9]+-[0-9]+$", port)) ?
            (tonumber(split("-", port)[0]) > 22 || tonumber(split("-", port)[1]) < 22) : false
          )
        )
      ])
      error_message = "With trusted_ssh_cidrs set, allowed_tcp_ports must include 22 and must not include another public port or range that overlaps TCP/22."
    }
  }
  dynamic "inbound_rule" {
    // With trusted SSH sources, TCP/22 gets its own restricted rule.
    for_each = var.trusted_ssh_cidrs == null ? var.allowed_tcp_ports : [for port in var.allowed_tcp_ports : port if port != "22"]
    content {
      protocol         = "tcp"
      port_range       = inbound_rule.value
      source_addresses = ["0.0.0.0/0"]
    }
  }

  dynamic "inbound_rule" {
    for_each = var.trusted_ssh_cidrs == null || !contains(var.allowed_tcp_ports, "22") ? [] : [1]
    content {
      protocol         = "tcp"
      port_range       = "22"
      source_addresses = var.trusted_ssh_cidrs
    }
  }

  dynamic "inbound_rule" {
    // Allow all UDP ports specified in the allowed_udp_ports variable from anywhere
    for_each = var.allowed_udp_ports
    content {
      protocol         = "udp"
      port_range       = inbound_rule.value
      source_addresses = ["0.0.0.0/0"]
    }
  }

  dynamic "inbound_rule" {
    // Allow engagement hosts to access each other
    for_each = ["tcp", "udp", "icmp"]
    content {
      protocol         = inbound_rule.value
      port_range       = "1-65535"
      source_addresses = [for ip in concat([for node in values(digitalocean_droplet.middle) : node.ipv4_address], [for node in values(digitalocean_droplet.edge) : node.ipv4_address]) : "${ip}/32"]
    }
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0"]
  }
}
