resource "linode_firewall" "firewall" {
  label           = "${var.engagement_name}-firewall"
  linodes         = flatten([linode_instance.middle.*.id, linode_instance.edge.*.id])
  tags            = [var.engagement_name]
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

  dynamic "inbound" {
    // Allow all TCP ports specified in the allowed_tcp_ports variable from anywhere
    for_each = var.allowed_tcp_ports
    content {
      label    = "allow-tcp-${inbound.value}"
      action   = "ACCEPT"
      protocol = "tcp"
      ports    = inbound.value
      ipv4     = ["0.0.0.0/0"]
    }
  }

  dynamic "inbound" {
    // Allow engagement hosts to access each other
    for_each = ["tcp", "udp", "icmp"]
    content {
      label    = "allow-${var.engagement_name}-host-${inbound.value}"
      action   = "ACCEPT"
      protocol = inbound.value
      // In all their genius, Linode doesn't append cidr /32 to their ipv4 addresses.
      // So we have to do it here with a for loop
      ipv4     = [for ip in flatten([linode_instance.middle.*.ipv4, linode_instance.edge.*.ipv4]): "${ip}/32"]
      // Uncomment to allow ipv6
      // ipv6     = flatten([linode_instance.middle.*.ipv6, linode_instance.edge.*.ipv6])
    }
  }

  dynamic "inbound" {
    // Block all IPv6 traffic inbound
    for_each = ["tcp", "udp", "icmp"]
    content {
      label    = "block-ipv6-${inbound.value}"
      action   = "DROP"
      protocol = inbound.value
      ipv6     = ["::/0"]
    }
  }

  dynamic "outbound" {
    // Block all IPv6 traffic outbound
    for_each = ["tcp", "udp", "icmp"]
    content {
      label    = "block-ipv6-${outbound.value}"
      action   = "DROP"
      protocol = outbound.value
      ipv6     = ["::/0"]
    }
  }
}
