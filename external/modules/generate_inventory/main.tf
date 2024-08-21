resource "local_file" "ansible_inventory" {
  filename = "../../ansible/inventory.ini"
  content = templatefile("../../templates/inventory.ini.tftpl", {
    aws_hosts = var.aws_hosts,
    oci_hosts = var.oci_hosts,
    linode_hosts = var.linode_hosts,
    # Add other necessary variables
  })
}