# Copyright (c) 2023, Oracle and/or its affiliates.

output "ubuntu-20-04-latest-name" {
  value = data.oci_core_images.ubuntu-20-04.images.0.display_name
}

resource "local_file" "ssh_stanza" {
  depends_on = [oci_core_instance.homebase]
  filename = pathexpand("${var.ssh_config_path}/${var.engagement_name}")
  file_permission = "0600"
  content = templatefile("../templates/ssh-stanza.tftpl", {
    engagement_name = var.engagement_name,
    homebase_ip = oci_core_instance.homebase.public_ip
  })
}


resource "local_file" "ansible_inventory" {
  depends_on = [oci_core_instance.homebase, oci_core_instance.proxy, oci_core_instance.elk]
  filename = "../../ansible/inventory.ini"
  file_permission = "0600"
  content = templatefile("../templates/inventory.ini.tftpl", {
    homebase = oci_core_instance.homebase.display_name,
    proxies  = { for instance in oci_core_instance.proxy: instance.display_name => instance.private_ip },
    elk      = { (oci_core_instance.elk.display_name) = oci_core_instance.elk.private_ip },
    username = var.image_username,
    key      = var.ssh_provisioning_private_key
  })
}

output "run-ansible" {
  value = "Add your ssh users.yml file to ../../ansible/playbooks make any modification you need to site.yml, homebase.yml, proxies.yml, elk.yml, then run ansible\n\n\tcd ../../ansible && ansible-playbook -i inventory.ini site.yml\n"
}

output "good-bye" {
  value = "Have a nice day!"
}

