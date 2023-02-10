# Copyright (c) 2023, Oracle and/or its affiliates.

# Define network resources for Red Team Infrastructure

# Virtual Cloud Network (VCN)
# https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingVCNs_topic-Overview_of_VCNs_and_Subnets.htm
# https://registry.terraform.io/providers/oracle/oci/latest/docs/resources/core_vcn

resource "oci_core_vcn" "infra_vcn" {
  cidr_block     = var.vcn_cidr_block
  compartment_id = var.compartment_id
  display_name   = format("%s-vcn", var.operation_name)
  dns_label      = format("%s", var.operation_name)
}

resource "oci_core_internet_gateway" "internet_gateway" {
  compartment_id = var.compartment_id
  display_name   = "vcn-shared-internet-gw"
  vcn_id         = oci_core_vcn.infra_vcn.id
}

resource "oci_core_route_table" "internet_gateway_route_table" {
  compartment_id = var.compartment_id
  display_name   = "vcn-shared-igw-route"
  vcn_id         = oci_core_vcn.infra_vcn.id

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.internet_gateway.id
  }
}

resource "oci_core_nat_gateway" "nat_gateway" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.infra_vcn.id
}

resource "oci_core_route_table" "nat_gateway_route_table" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.infra_vcn.id

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_nat_gateway.nat_gateway.id
  }
}

# Subnets
# https://registry.terraform.io/providers/oracle/oci/latest/docs/resources/core_subnet
resource "oci_core_subnet" "infra" {
  depends_on = [oci_core_vcn.infra_vcn]

  compartment_id      = var.compartment_id
  availability_domain = data.oci_identity_availability_domain.ad.name
  vcn_id              = oci_core_vcn.infra_vcn.id

  security_list_ids = [
    oci_core_security_list.vcn_all.id,
    oci_core_security_list.all_egress_list.id,
    oci_core_security_list.ssh_from_company.id
  ]

  route_table_id = oci_core_route_table.internet_gateway_route_table.id

  display_name = "infra-subnet"
  dns_label    = "infra"
  cidr_block   = var.subnet_cidr_blocks["infra"]
}

resource "oci_core_subnet" "utility" {
  depends_on = [oci_core_vcn.infra_vcn]

  compartment_id      = var.compartment_id
  availability_domain = data.oci_identity_availability_domain.ad.name
  vcn_id              = oci_core_vcn.infra_vcn.id

  security_list_ids = [
    oci_core_security_list.vcn_all.id,
    oci_core_security_list.all_egress_list.id
  ]

  route_table_id = oci_core_route_table.nat_gateway_route_table.id

  display_name = "utility-subnet"
  dns_label    = "utility"
  cidr_block   = var.subnet_cidr_blocks["utility"]
}

resource "oci_core_subnet" "proxy" {
  depends_on = [oci_core_vcn.infra_vcn]

  compartment_id      = var.compartment_id
  availability_domain = data.oci_identity_availability_domain.ad.name
  vcn_id              = oci_core_vcn.infra_vcn.id

  security_list_ids = [
    oci_core_security_list.vcn_all.id,
    oci_core_security_list.all_egress_list.id,
  ]

  route_table_id = oci_core_route_table.internet_gateway_route_table.id

  display_name = "proxy-subnet"
  dns_label    = "proxy"
  cidr_block   = var.subnet_cidr_blocks["proxy"]
}


# DHCP-Options
# https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingDHCP.htm
# https://registry.terraform.io/providers/oracle/oci/latest/docs/resources/core_dhcp_options
resource "oci_core_default_dhcp_options" "default-dhcp-options" {
  manage_default_resource_id = oci_core_vcn.infra_vcn.default_dhcp_options_id
  options {
    type               = "DomainNameServer"
    server_type        = "CustomDnsServer"
    custom_dns_servers = ["8.8.8.8", "1.1.1.1"]
  }
}

# Security Lists
# https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securitylists.htm
# https://registry.terraform.io/providers/oracle/oci/latest/docs/resources/core_security_list
resource "oci_core_security_list" "vcn_all" {
  compartment_id = var.compartment_id
  display_name   = "VCN All - traffic flows freely inside VCN"
  vcn_id         = oci_core_vcn.infra_vcn.id

  # create egress rules for each protocol
  dynamic "egress_security_rules" {
    for_each = var.network_protocol
    content {
      protocol    = egress_security_rules.value
      destination = "192.168.0.0/16"
    }
  }

  # create ingress rules for each protocol
  dynamic "ingress_security_rules" {
    for_each = var.network_protocol
    content {
      protocol = ingress_security_rules.value
      source   = "192.168.0.0/16"
    }
  }
}

resource "oci_core_security_list" "all_egress_list" {
  compartment_id = var.compartment_id
  display_name   = "all-egress-list"
  vcn_id         = oci_core_vcn.infra_vcn.id

  dynamic "egress_security_rules" {
    for_each = var.network_protocol
    content {
      destination = "0.0.0.0/0"
      protocol    = egress_security_rules.value
    }
  }
}

resource "oci_core_security_list" "ssh_from_anywhere" {
  compartment_id = var.compartment_id
  display_name   = "SSH from Anywhere"
  vcn_id         = oci_core_vcn.infra_vcn.id


  ingress_security_rules {
    protocol = var.network_protocol["tcp"]
    source   = "0.0.0.0/0"

    tcp_options {
      min = 22
      max = 22
    }
  }
}

resource "oci_core_security_list" "ssh_from_company" {
  compartment_id = var.compartment_id
  display_name   = "SSH from company"
  vcn_id         = oci_core_vcn.infra_vcn.id

  # Allow SSH for each allowed subnet in variables.tfvars
  dynamic "ingress_security_rules" {
    for_each = var.ssh_allowed_cidr_ranges

    content {
      protocol = var.network_protocol["tcp"]
      tcp_options {
        min = 22
        max = 22
      }
      source = ingress_security_rules.value
    }
  }
}

# Network Security Groups (NSG)
# https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/networksecuritygroups.htm
# https://registry.terraform.io/providers/oracle/oci/latest/docs/resources/core_network_security_group
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

resource "oci_core_network_security_group_security_rule" "http_alt" {
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

resource "oci_core_network_security_group_security_rule" "ssh_alt" {
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