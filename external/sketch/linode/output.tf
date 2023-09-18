resource "local_file" "ssh_stanza" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filename = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
  file_permission = "0600"
  content = templatefile("templates/ssh-stanza.tftpl", {
    engagement_name = var.engagement_name,
    ssh_private_key = var.ssh_private_key
    middles = linode_instance.middle.*,
    edges = linode_instance.edge.*
  })
}

resource "local_file" "ansible_inventory" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filename = "inventory.ini"
  file_permission = "0600"
  content = templatefile("templates/inventory.tftpl", {
    middles = linode_instance.middle.*,
    edges = linode_instance.edge.*
  })
}

output "run-ansible" {
  depends_on = [local_file.ansible_inventory]
  value = "Run ansible to configure hosts with:\n\tansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini -e \"ssh_key=${var.ssh_public_key}\" -e \"ssh_config_path=${local.abs_ssh_config_path}\""
}

output "good-bye" {
  depends_on = [local_file.ansible_inventory]
  value = "Have a nice day!"
}
