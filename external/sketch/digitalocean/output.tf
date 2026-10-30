# Copyright (c) 2026, Oracle and/or its affiliates.
resource "local_file" "ssh_stanza" {
  count           = length(local.middle_nodes) > 0 && length(local.edge_nodes) > 0 && !local.uses_external_middle ? 1 : 0
  depends_on      = [digitalocean_droplet.middle, digitalocean_droplet.edge]
  filename        = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
  file_permission = "0600"
  content = templatefile("templates/ssh-stanza.tftpl", {
    engagement_name = var.engagement_name,
    ssh_private_key = local.ssh_priv_key_path
    middles         = [for name in sort(keys(digitalocean_droplet.middle)) : digitalocean_droplet.middle[name]],
    edges           = [for name in local.edge_output_order : { node = digitalocean_droplet.edge[name], middle_name = digitalocean_droplet.middle[local.edge_nodes[name].middle_node].name }]
  })
}

resource "local_file" "ansible_inventory" {
  count           = length(local.middle_nodes) > 0 && length(local.edge_nodes) > 0 && !local.uses_external_middle ? 1 : 0
  depends_on      = [digitalocean_droplet.middle, digitalocean_droplet.edge]
  filename        = "inventory.ini"
  file_permission = "0600"
  content = templatefile("templates/inventory.tftpl", {
    middles           = [for name in sort(keys(digitalocean_droplet.middle)) : digitalocean_droplet.middle[name]],
    edges             = [for name in local.edge_output_order : { node = digitalocean_droplet.edge[name] }],
    ssh_priv_key_path = local.ssh_priv_key_path,
    engagement_name   = var.engagement_name
  })
}

output "public-key" {
  value = local.ssh_pub_key_path

  precondition {
    condition     = !local.keyed_topology || (var.middles != null && var.edge_groups != null && var.middle_region == null && length(var.edge_regions) == 0 && var.middle_count == 1 && var.edge_count_per_region == 1)
    error_message = "Set both middles and edge_groups for keyed topology, without legacy topology variables."
  }

  precondition {
    condition     = !local.keyed_topology || (length(setintersection(toset(keys(local.middle_nodes)), var.external_middle_nodes)) == 0 && alltrue([for group in values(local.effective_edge_groups) : contains(keys(local.middle_nodes), group.middle_node) || contains(var.external_middle_nodes, group.middle_node)]))
    error_message = "Each edge group's middle_node must name a local middle or a declared external middle; local and external names must be distinct."
  }
}

output "run-ansible" {
  depends_on = [local_file.ansible_inventory]
  value      = "Run ansible to configure hosts with:\n\tansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini -e \"ssh_pub_key=${local.ssh_pub_key_path}\" -e \"ssh_config_path=${local.abs_ssh_config_path}\""
}

output "middle_public_ips" {
  value = [for name in sort(keys(digitalocean_droplet.middle)) : digitalocean_droplet.middle[name].ipv4_address]
}

output "middle_instance_ids" {
  value = [for name in sort(keys(digitalocean_droplet.middle)) : digitalocean_droplet.middle[name].id]
}

output "edge_public_ips" {
  value = [for name in local.edge_output_order : digitalocean_droplet.edge[name].ipv4_address]
}

output "edge_instance_ids" {
  value = [for name in local.edge_output_order : digitalocean_droplet.edge[name].id]
}

output "middle_nodes" {
  value = { for name, instance in digitalocean_droplet.middle : name => { id = instance.id, public_ip = instance.ipv4_address, name = instance.name } }
}

output "edge_nodes" {
  value = { for name, instance in digitalocean_droplet.edge : name => { id = instance.id, public_ip = instance.ipv4_address, name = instance.name, middle_node = local.edge_nodes[name].middle_node } }
}

output "good-bye" {
  depends_on = [local_file.ansible_inventory]
  value      = "Have a nice day!"
}
