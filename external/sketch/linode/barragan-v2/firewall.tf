# Copyright (c) 2026, Oracle and/or its affiliates.
resource "linode_firewall" "firewall" {
  label           = "fw-${var.engagement_name}-firewall"
  linodes         = concat([for node in values(linode_instance.middle) : node.id], [for node in values(linode_instance.edge) : node.id])
  tags            = [var.engagement_name]
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

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

  dynamic "inbound" {
    // With trusted SSH sources, TCP/22 gets its own restricted rule.
    for_each = var.trusted_ssh_cidrs == null ? var.allowed_tcp_ports : [for port in var.allowed_tcp_ports : port if port != "22"]
    content {
      label    = "allow-tcp-${inbound.value}"
      action   = "ACCEPT"
      protocol = "TCP"
      ports    = inbound.value
      ipv4     = ["0.0.0.0/0"]
    }
  }

  dynamic "inbound" {
    for_each = var.trusted_ssh_cidrs == null || !contains(var.allowed_tcp_ports, "22") ? [] : [1]
    content {
      label    = "allow-tcp-22-trusted"
      action   = "ACCEPT"
      protocol = "TCP"
      ports    = "22"
      ipv4     = var.trusted_ssh_cidrs
    }
  }

  dynamic "inbound" {
    for_each = var.allowed_udp_ports
    content {
      label    = "allow-udp-${inbound.value}"
      action   = "ACCEPT"
      protocol = "UDP"
      ports    = inbound.value
      ipv4     = ["0.0.0.0/0"]
    }
  }

  dynamic "inbound" {
    // Allow engagement hosts to access each other
    for_each = ["TCP", "UDP", "ICMP"]
    content {
      label    = "allow-${var.engagement_name}-host-${lower(inbound.value)}"
      action   = "ACCEPT"
      protocol = inbound.value
      // In all their genius, Linode doesn't append cidr /32 to their ipv4 addresses.
      // So we have to do it here with a for loop
      ipv4 = [for ip in flatten(concat([for node in values(linode_instance.middle) : node.ipv4], [for node in values(linode_instance.edge) : node.ipv4])) : "${ip}/32"]
      // Uncomment to allow ipv6
      // ipv6     = flatten([linode_instance.middle.*.ipv6, linode_instance.edge.*.ipv6])
    }
  }

  dynamic "inbound" {
    // Block all IPv6 traffic inbound
    for_each = ["TCP", "UDP", "ICMP"]
    content {
      label    = "block-ipv6-${lower(inbound.value)}"
      action   = "DROP"
      protocol = inbound.value
      ipv6     = ["::/0"]
    }
  }

  dynamic "outbound" {
    // Block all IPv6 traffic outbound
    for_each = ["TCP", "UDP", "ICMP"]
    content {
      label    = "block-ipv6-${lower(outbound.value)}"
      action   = "DROP"
      protocol = outbound.value
      ipv6     = ["::/0"]
    }
  }
}
