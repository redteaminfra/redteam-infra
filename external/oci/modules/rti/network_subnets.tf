resource "oci_core_subnet" "infra" {
  depends_on = ["oci_core_vcn.infra_vcn"]

  compartment_id      = "${var.compartment_id}"
  availability_domain = "${data.null_data_source.target_ad.outputs.name}"
  vcn_id              = "${oci_core_vcn.infra_vcn.id}"

  security_list_ids = [
    "${oci_core_security_list.vcn_all.id}",
    "${oci_core_security_list.all_egress_list.id}",
    "${oci_core_security_list.ssh_from_company.id}"
  ]

  route_table_id  = "${oci_core_route_table.igw.id}"

  display_name = "infra-subnet"
  dns_label    = "infra"
  cidr_block   = "${var.infra_subnet_cidr}"
}

resource "oci_core_subnet" "utility" {
  depends_on = ["oci_core_vcn.infra_vcn"]

  compartment_id      = "${var.compartment_id}"
  availability_domain = "${data.null_data_source.target_ad.outputs.name}"
  vcn_id              = "${oci_core_vcn.infra_vcn.id}"

  security_list_ids = [
    "${oci_core_security_list.vcn_all.id}",
    "${oci_core_security_list.all_egress_list.id}"
  ]

  route_table_id  = "${oci_core_route_table.igw.id}"

  display_name = "utility-subnet"
  dns_label    = "utility"
  cidr_block   = "${var.utility_cidr}"
}

resource "oci_core_subnet" "proxy" {
  depends_on = ["oci_core_vcn.infra_vcn"]

  compartment_id      = "${var.compartment_id}"
  availability_domain = "${data.null_data_source.target_ad.outputs.name}"
  vcn_id              = "${oci_core_vcn.infra_vcn.id}"

  security_list_ids = [
    "${oci_core_security_list.vcn_all.id}",
    "${oci_core_security_list.all_egress_list.id}",
    "${oci_core_security_list.https_from_anywhere.id}",
    "${oci_core_security_list.http_from_anywhere.id}",
    "${oci_core_security_list.ssh_2222_from_anywhere.id}"
  ]

  route_table_id  = "${oci_core_route_table.igw.id}"

  display_name = "proxy-subnet"
  dns_label    = "proxy"
  cidr_block   = "${var.proxy_cidr}"
}
