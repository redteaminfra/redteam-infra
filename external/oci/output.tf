output "ubuntu-20-04-latest-name" {
  value = data.oci_core_images.ubuntu-20-04.images.0.display_name
}

output "good-bye" {
  value = "Have a nice day!"
}