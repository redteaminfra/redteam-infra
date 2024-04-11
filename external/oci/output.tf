# Copyright (c) 2023, Oracle and/or its affiliates.

output "ubuntu-version-name" {
  value = data.oci_core_images.ubuntu-version.images.0.display_name
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

resource "local_sensitive_file" "ssh_private_key" {
  content = tls_private_key.ssh_key.private_key_openssh
  filename = pathexpand("~/.ssh/${var.engagement_name}")
  file_permission = "0600"
}

resource "local_file" "ssh_public_key" {
  content = tls_private_key.ssh_key.public_key_openssh
  filename = pathexpand("~/.ssh/${var.engagement_name}.pub")
  file_permission = "0600"
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
    key      = local_sensitive_file.ssh_private_key.filename
  })
}

resource "local_file" "oci_instance_backup" {
  count = var.is_production ? 1 : 0
  depends_on = [oci_core_instance.homebase, oci_core_instance.proxy, oci_core_instance.elk]
  filename = "oci-instance-backup.sh"
  file_permission = "0755"
  content = templatefile("../templates/oci-instance-backup.sh.tftpl", {
    hosts = merge(
        {for instance in oci_core_instance.homebase.* : instance.display_name => instance.boot_volume_id},
        {for instance in oci_core_instance.proxy : instance.display_name => instance.boot_volume_id},
        {for instance in oci_core_instance.elk.* : instance.display_name => instance.boot_volume_id}
      ),
    config_file_profile = var.config_file_profile,
    compartment_id = var.compartment_id,
    engagement_name = var.engagement_name,
    region = var.region,
    backup_compartment_id = var.backup_compartment_id,
  })
}

output "run-ansible" {
  value = "Add your ssh users.yml file to ../../ansible/playbooks make any modification you need to site.yml, homebase.yml, proxies.yml, elk.yml, then run ansible\n\n\tcd ../../ansible && ansible-playbook -i inventory.ini site.yml\n"
}

output "proxy_public_ips" {
  value = [for ip in oci_core_instance.proxy : ip.public_ip]
}

output "good-bye" {
  value = "Have a nice day!"
}

