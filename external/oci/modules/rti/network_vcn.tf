resource "oci_core_vcn" "infra_vcn" {
  cidr_block     = "${var.vcn_cidr_block}"
  compartment_id = "${var.compartment_id}"
  display_name   = "${format("%s-vcn", var.op_name)}"
  dns_label      = "${format("%s", var.op_name)}"
}

resource "oci_core_internet_gateway" "igw" {
  compartment_id = "${var.compartment_id}"
  display_name   = "vcn-shared-internet-gw"
  vcn_id         = "${oci_core_vcn.infra_vcn.id}"
}

resource "oci_core_route_table" "igw" {
  compartment_id = "${var.compartment_id}"
  display_name   = "vcn-shared-igw-route"
  vcn_id         = "${oci_core_vcn.infra_vcn.id}"

  route_rules = [
    {
      destination       = "0.0.0.0/0"
      network_entity_id = "${oci_core_internet_gateway.igw.id}"
    }
  ]
}
