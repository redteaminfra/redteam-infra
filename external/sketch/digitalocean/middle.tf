resource "digitalocean_droplet" "middle" {
  name           = "middle${format("%02g", count.index + 1)}-${var.engagement_name}"
  region          = var.middle_region
  count           = var.middle_count
  size            = var.middle_size
  image           = var.docean_image
  tags            = [var.engagement_name]
  ssh_keys = [digitalocean_ssh_key.key.id]
}
