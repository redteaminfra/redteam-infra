resource "digitalocean_firewall" "firewall" {
  name        = "${var.engagement_name}-firewall"
  droplet_ids = flatten([digitalocean_droplet.middle.*.id, digitalocean_droplet.edge.*.id])
  tags        = [var.engagement_name]
  inbound_rule {
    protocol         = "tcp"
    port_range       = "1-65535"
    source_addresses = ["0.0.0.0/0"]
  }

  dynamic "inbound_rule" {
    // Allow all TCP ports specified in the allowed_tcp_ports variable from anywhere
    for_each = var.allowed_tcp_ports
    content {
      protocol         = "tcp"
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
      source_addresses = [for ip in flatten([digitalocean_droplet.middle.*.ipv4_address, digitalocean_droplet.edge.*.ipv4_address]): "${ip}/32"]
    }
  }

  dynamic "inbound_rule" {
    // Block all IPv6 traffic inbound
    for_each = ["tcp", "udp", "icmp"]
    content {
      protocol         = inbound_rule.value
      port_range       = "1-65535"
      source_addresses = ["::/0"]
    }
  }

  outbound_rule {
    protocol           = "tcp"
    port_range         = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  dynamic "outbound_rule" {
    // Block all IPv6 traffic outbound
    for_each = ["tcp", "udp", "icmp"]
    content {
      protocol              = outbound_rule.value
      port_range            = "1-65535"
      destination_addresses = ["::/0"]
    }
  }

  outbound_rule {
    protocol                = "icmp"
    destination_addresses = ["0.0.0.0/0"]
  }
}
