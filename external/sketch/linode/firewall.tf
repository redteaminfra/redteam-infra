resource "linode_firewall" "firewall" {
  label           = "${var.engagement_name}-firewall"
  linodes         = flatten([linode_instance.middle.*.id, linode_instance.edge.*.id])
  tags            = [var.engagement_name]
  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

  inbound {
    label    = "allow-ssh"
    action   = "ACCEPT"
    protocol = "tcp"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
  }

  inbound {
    label    = "allow-http"
    action   = "ACCEPT"
    protocol = "tcp"
    ports    = "80"
    ipv4     = ["0.0.0.0/0"]
  }

  inbound {
    label    = "allow-https"
    action   = "ACCEPT"
    protocol = "tcp"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
  }

  inbound {
    label    = "allow-2222"
    action   = "ACCEPT"
    protocol = "tcp"
    ports    = "2222"
    ipv4     = ["0.0.0.0/0"]
  }

  inbound {
    label    = "block-ipv6-tcp"
    action   = "DROP"
    protocol = "tcp"
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "block-ipv6-udp"
    action   = "DROP"
    protocol = "udp"
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "block-ipv6-icmp"
    action   = "DROP"
    protocol = "icmp"
    ipv6     = ["::/0"]
  }

  outbound {
    label    = "block-ipv6-tcp"
    action   = "DROP"
    protocol = "tcp"
    ipv6     = ["::/0"]
  }

  outbound {
    label    = "block-ipv6-udp"
    action   = "DROP"
    protocol = "udp"
    ipv6     = ["::/0"]
  }

  outbound {
    label    = "block-ipv6-icmp"
    action   = "DROP"
    protocol = "icmp"
    ipv6     = ["::/0"]
  }
}