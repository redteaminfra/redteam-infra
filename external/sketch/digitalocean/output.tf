resource "local_file" "ssh_stanza" {
  depends_on = [digitalocean_droplet.middle, digitalocean_droplet.edge]
  filename = pathexpand("${var.ssh_config_path}/${var.engagement_name}-sketch")
  file_permission = "0600"
  content = templatefile("templates/ssh-stanza.tftpl", {
    engagement_name = var.engagement_name,
    ssh_private_key = local.ssh_priv_key_path
    middles = digitalocean_droplet.middle.*,
    edges = digitalocean_droplet.edge.*
  })
}

resource "local_file" "ansible_inventory" {
  depends_on = [digitalocean_droplet.middle, digitalocean_droplet.edge]
  filename = "inventory.ini"
  file_permission = "0600"
  content = templatefile("templates/inventory.tftpl", {
    middles = digitalocean_droplet.middle.*,
    edges = digitalocean_droplet.edge.*,
    ssh_priv_key_path = local.ssh_priv_key_path,
    engagement_name = var.engagement_name
  })
}

output "public-key" {
  value = "${local.ssh_pub_key_path}"
}

output "run-ansible" {
  depends_on = [local_file.ansible_inventory]
  value = "Run ansible to configure hosts with:\n\tansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini -e \"ssh_pub_key=${local.ssh_pub_key_path}\" -e \"ssh_config_path=${local.abs_ssh_config_path}\""
}

output "middle_public_ips" {
  value = [for ip in digitalocean_droplet.middle: ip.ipv4_address]
}

output "good-bye" {
  depends_on = [local_file.ansible_inventory]
  value = "Have a nice day!"
}
