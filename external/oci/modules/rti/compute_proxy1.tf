resource "oci_core_instance" "proxy01" {
  depends_on          = [oci_core_instance.homebase]
  availability_domain = data.null_data_source.target_ad.outputs.name
  compartment_id      = var.compartment_id
  display_name        = "${var.proxy_name}01-${var.op_name}"
  shape               = var.proxy_shape

  source_details {
    source_id   = var.ubuntu_image_id[var.region]
    source_type = "image"
  }

  create_vnic_details {
    subnet_id      = oci_core_subnet.proxy.id
    hostname_label = "${var.proxy_name}01-${var.op_name}"

    private_ip             = cidrhost(var.proxy_cidr, 11)
    assign_public_ip       = false
    skip_source_dest_check = "true"
    nsg_ids = [
      "${oci_core_network_security_group.proxies.id}"
    ]
  }

  metadata = {
    ssh_authorized_keys = "${file(var.ssh_provisioning_public_key)}"
    user_data           = base64encode(file("../global/host-share/user_data.yml"))
  }
}

data "oci_core_private_ips" "proxy01" {
  ip_address = oci_core_instance.proxy01.private_ip
  subnet_id  = oci_core_subnet.proxy.id
}

resource "oci_core_public_ip" "proxy01" {
  compartment_id = var.compartment_id
  lifetime       = "EPHEMERAL"

  display_name  = "Proxy01 public ip"
  private_ip_id = lookup(data.oci_core_private_ips.proxy01.private_ips[0], "id")
}

resource "null_resource" "proxy01_provisioner" {
  depends_on = [oci_core_instance.proxy01]

  connection {
    host        = oci_core_instance.proxy01.private_ip
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
    source      = "../global/proxies"
    destination = "/tmp/host-share/"
  }

  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/host-share/puppet/manifests",
      "ln -s /tmp/host-share/proxies/puppet//manifests/site.pp /tmp/host-share/puppet/manifests/site.pp",
      "if [ ! -L /etc/infra/site ]; then sudo mkdir -p /etc/infra && sudo ln -s external/global/proxies/puppet/manifests/site.pp /etc/infra/site; fi",
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
