resource "oci_core_instance" "elk" {
  depends_on          = [oci_core_instance.homebase]
  availability_domain = data.null_data_source.target_ad.outputs.name
  compartment_id      = var.compartment_id
  display_name        = "elk-${var.op_name}"
  shape               = var.infra_shape

  source_details {
    source_id   = var.ubuntu_image_id
    source_type = "image"
  }

  create_vnic_details {
    subnet_id      = oci_core_subnet.utility.id
    hostname_label = "elk-${var.op_name}"

    private_ip = cidrhost(var.utility_cidr, 13)
  }

  metadata = {
    ssh_authorized_keys = "${file(var.ssh_provisioning_public_key)}"
  }

  preserve_boot_volume = var.preserve_boot_volume
}

resource "null_resource" "elk_provisioner" {
  depends_on = [oci_core_instance.elk]

  connection {
    host        = oci_core_instance.elk.private_ip
    type        = "ssh"
    user        = var.instance_user
    private_key = file(var.ssh_provisioning_private_key)
    timeout     = "3m"

    bastion_host = oci_core_public_ip.homebase.ip_address
    bastion_user = var.homebase_user
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
      "sudo bash -e /tmp/host-share/setup.sh",
      "sudo bash -e /tmp/host-share/oci_iptables_fix.sh",
    ]
  }
}
