resource "oci_core_network_security_group" "proxies" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.infra_vcn.id
  display_name   = "Proxy Security Group"
}

resource "oci_core_network_security_group_security_rule" "https" {
  network_security_group_id = oci_core_network_security_group.proxies.id

  description = "HTTPS"
  direction   = "INGRESS"
  protocol    = 6
  source_type = "CIDR_BLOCK"
  source      = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 443
      max = 443
    }
  }
}

resource "oci_core_network_security_group_security_rule" "http" {
  network_security_group_id = oci_core_network_security_group.proxies.id

  description = "HTTP"
  direction   = "INGRESS"
  protocol    = 6
  source_type = "CIDR_BLOCK"
  source      = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 80
      max = 80
    }
  }
}

resource "oci_core_network_security_group_security_rule" "httpalt" {
  network_security_group_id = oci_core_network_security_group.proxies.id

  description = "HTTP ALT"
  direction   = "INGRESS"
  protocol    = 6
  source_type = "CIDR_BLOCK"
  source      = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 8000
      max = 8080
    }
  }
}

resource "oci_core_network_security_group_security_rule" "sshalt" {
  network_security_group_id = oci_core_network_security_group.proxies.id

  description = "SSH ALT"
  direction   = "INGRESS"
  protocol    = 6
  source_type = "CIDR_BLOCK"
  source      = "0.0.0.0/0"
  tcp_options {
    destination_port_range {
      min = 2222
      max = 2222
    }
  }
}
