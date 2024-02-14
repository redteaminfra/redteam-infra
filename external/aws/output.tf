output "ubuntu-20-04-latest-name" {
  value = data.aws_ami.ubuntu.description
}

//Builds the ssh config and puts it in the file path specified in vars
resource "local_file" "ssh_stanza" {
  depends_on = [aws_instance.homebase]
  filename = pathexpand("${var.ssh_config_path}/${var.engagement_name}")
  file_permission = "0600"
  content = templatefile("../templates/ssh-stanza.tftpl", {
    engagement_name = var.engagement_name,
    homebase_ip = aws_instance.homebase.public_ip
  })
}
//Builds the inventory for Ansible
resource "local_file" "ansible_inventory" {
  depends_on = [aws_instance.homebase, aws_instance.proxy, aws_instance.elk]
  filename = "../../ansible/inventory.ini"
  file_permission = "0600"
  content = templatefile("../templates/inventory.ini.tftpl", {
    homebase = aws_instance.homebase.tags.Name
    proxies  = { for aws_instance in aws_instance.proxy: aws_instance.tags.Name => aws_instance.private_ip },
    elk      = { (aws_instance.elk.tags.Name) = aws_instance.elk.private_ip },
    username = var.image_username,
    key      = var.key_name
  })
}

output "run-ansible" {
  value = "Add your ssh users.yml file to ../../ansible/playbooks make any modification you need to site.yml, homebase.yml, proxies.yml, elk.yml, then run ansible\n\n\tcd ../../ansible && ansible-playbook -i inventory.ini site.yml\n"
}
output "good-bye" {
  value = "Have a nice day!"
}