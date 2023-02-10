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

output "good-bye" {
  value = "Have a nice day!"
}