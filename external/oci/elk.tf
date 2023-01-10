# Copyright (c) 2023, Oracle and/or its affiliates.

resource "oci_core_instance" "elk" {
  depends_on          = [oci_core_instance.homebase]
  availability_domain = data.oci_identity_availability_domain.ad.name
  compartment_id      = var.compartment_id
  display_name        = "elk-${var.operation_name}"
  shape               = var.elk_shape

  source_details {
    source_id               = data.oci_core_images.ubuntu-20-04.images.0.id
    source_type             = "image"
    boot_volume_size_in_gbs = var.boot_volume_size_in_gbs
  }

  create_vnic_details {
    subnet_id      = oci_core_subnet.utility.id
    hostname_label = "elk-${var.operation_name}"

    private_ip       = cidrhost(var.subnet_cidr_blocks["utility"], 13)
    assign_public_ip = false
  }

  metadata = {
    ssh_authorized_keys = "${file(var.ssh_provisioning_public_key)}"
    #    user_data           = base64encode(file("../global/host-share/user_data.yml"))
  }

  agent_config {
    are_all_plugins_disabled = true
    is_monitoring_disabled   = true
    plugins_config {
      name          = "Compute Instance Monitoring"
      desired_state = "DISABLED"
    }
  }

  preserve_boot_volume = var.preserve_boot_volume

  connection {
    host        = self.private_ip
    type        = "ssh"
    user        = var.image_username
    private_key = file(var.ssh_provisioning_private_key)
    timeout     = "3m"

    bastion_host = oci_core_instance.homebase.public_ip
    bastion_user = var.image_username
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/",
    ]
  }

  provisioner "file" {
    source      = "../global/host-share/"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source      = "../../puppet"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source      = "../global/elkServer"
    destination = "/tmp/host-share/"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/elkServer/puppet/manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/elkServer/puppet/manifests/site.pp /etc/infra/site; fi",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait"
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -e /tmp/host-share/finish.sh",
      "sudo bash -e /tmp/host-share/oci_iptables_fix.sh",
    ]
  }
}