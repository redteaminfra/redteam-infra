resource "oci_core_instance" "homebase" {
  availability_domain = "${data.null_data_source.target_ad.outputs.name}"
  compartment_id      = "${var.compartment_id}"
  display_name        = "homebase-${var.op_name}"
  shape               = "${var.infra_shape}"

  source_details {
    source_id = "${var.ubuntu_image_id}"
    source_type = "image"
  }

  create_vnic_details {
    subnet_id = "${oci_core_subnet.infra.id}"
    hostname_label = "homebase-${var.op_name}"

    private_ip = "${cidrhost(var.infra_subnet_cidr, 10)}"
    assign_public_ip = false
  }

  metadata {
    ssh_authorized_keys = "${file(var.ssh_provisioning_public_key)}"
  }

  preserve_boot_volume = "${var.preserve_boot_volume}"
}

data "oci_core_private_ips" "homebase" {
  ip_address = "${oci_core_instance.homebase.private_ip}"
  subnet_id = "${oci_core_subnet.infra.id}"
}

resource "oci_core_public_ip" "homebase" {
  compartment_id = "${var.compartment_id}"
  lifetime = "EPHEMERAL"

  display_name = "Homebase public ip"
  private_ip_id = "${lookup(data.oci_core_private_ips.homebase.private_ips[0],"id")}"
}

resource "null_resource" "homebase_provisioner" {
 depends_on = ["oci_core_instance.homebase"]

 connection {
   host = "${oci_core_public_ip.homebase.ip_address}"
   type = "ssh"
   user = "${var.homebase_user}"
   private_key = "${file(var.ssh_provisioning_private_key)}"
   timeout = "3m"
 }

  provisioner "local-exec" {
    command = "bash -c \"cd $(git rev-parse --show-toplevel); tar -czf external/global/host-share/bootstrap-puppet.tgz .git\""
  }

  provisioner "local-exec" {
    command = "../global/generate_ssh_stanza.rb --opname ${var.op_name} --homebase_ip ${oci_core_public_ip.homebase.ip_address}"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/",
    ]
  }

  provisioner "file" {
    source = "../global/host-share/"
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../../puppet",
    destination = "/tmp/host-share/"
  }

  provisioner "file" {
    source = "../global/homebase",
    destination = "/tmp/host-share/"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/homebase/puppet/manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/homebase/puppet/manifests/site.pp /etc/infra/site; fi",
    ]
  }

  provisioner "remote-exec" {
    inline = [
      "sudo bash -e /tmp/host-share/setup.sh",
      "sudo bash -c 'iptables -F INPUT; iptables -F FORWARD; iptables -F OUTPUT; iptables -F InstanceServices; iptables -L'",
   ]
  }
}
