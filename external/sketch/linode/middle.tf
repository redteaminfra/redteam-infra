resource "linode_instance" "middle" {
  label           = "middle${format("%02g", count.index + 1)}-${var.engagement_name}"
  region          = var.middle_region
  count           = var.middle_count
  type            = var.middle_type
  image           = var.linode_image
  tags            = [var.engagement_name]
  root_pass       = random_password.root_password.result
  authorized_keys = [chomp(file(local.ssh_pub_key_path))]
}
