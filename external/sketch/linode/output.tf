data "linode_instances" "all-compute" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filter {
    name = "tags"
    values = [var.engagement_name]
  }
}

data "linode_instances" "edge" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filter {
    name   = "tags"
    values = [var.engagement_name]
  }

    filter {
    name     = "label"
    values   = ["edge"]
    match_by = "substring"
  }
}

data "linode_instances" "middle" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filter {
    name   = "tags"
    values = [var.engagement_name]
  }

  filter {
    name     = "label"
    values   = ["middle"]
    match_by = "substring"
  }
}

resource "local_file" "ssh_stanza" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filename = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
  file_permission = "0600"
  content = templatefile("templates/ssh-stanza.tftpl", {
    engagement_name = var.engagement_name,
    ssh_private_key = var.ssh_private_key
    middles = data.linode_instances.middle.instances.*,
    edges = data.linode_instances.edge.instances.*
  })
}

resource "local_file" "ansible_inventory" {
  depends_on = [linode_instance.middle, linode_instance.edge]
  filename = "inventory.ini"
  file_permission = "0600"
  content = templatefile("templates/inventory.tftpl", {
    middles = data.linode_instances.middle.instances.*,
    edges = data.linode_instances.edge.instances.*
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