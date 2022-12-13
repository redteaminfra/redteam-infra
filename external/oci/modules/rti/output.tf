output "ubuntu-20-04-latest-id" {
  value = data.oci_core_images.ubuntu-20-04.images.0.id
}