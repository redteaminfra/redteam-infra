# Copyright (c) 2023, Oracle and/or its affiliates.

resource "oci_core_instance" "proxy" {
  depends_on          = [oci_core_instance.homebase]
  availability_domain = data.oci_identity_availability_domain.ad.name
  compartment_id      = var.compartment_id
  display_name        = "proxy${format("%02g", count.index + 1)}-${var.engagement_name}"
  shape               = var.proxy_shape
  count               = var.proxy_count
  freeform_tags       = local.tags

  source_details {
    source_id               = data.oci_core_images.ubuntu-version.images.0.id
    source_type             = "image"
    boot_volume_size_in_gbs = var.boot_volume_size_in_gbs
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  create_vnic_details {
    subnet_id = oci_core_subnet.proxy.id
    #    display_name   = "proxy${format("%02g", count.index + 1)}-${var.operation_name}"

    private_ip             = cidrhost(var.subnet_cidr_blocks["proxy"], count.index + 11)
    assign_public_ip       = true
    skip_source_dest_check = true
    nsg_ids                = [
      oci_core_network_security_group.proxies.id
    ]
  }

  metadata = {
    ssh_authorized_keys = file(var.ssh_provisioning_public_key)
  }

  agent_config {
    are_all_plugins_disabled = true
    is_monitoring_disabled   = true
    plugins_config {
      name          = "Compute Instance Monitoring"
      desired_state = "DISABLED"
    }
  }
}
