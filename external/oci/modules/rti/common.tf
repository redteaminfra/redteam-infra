data "oci_identity_availability_domains" "ads" {
  compartment_id   = "${var.compartment_id}"
}

data "null_data_source" "target_ad" {
  inputs = {
    name = "${lookup(data.oci_identity_availability_domains.ads.availability_domains[var.avail_dom], "name")}"
  }
}
