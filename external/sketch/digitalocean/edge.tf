resource "digitalocean_droplet" "edge" {
  name           = "edge-${var.engagement_name}-${element(var.edge_regions, floor(count.index / var.edge_count_per_region))}-${format("%02g", (count.index % var.edge_count_per_region) + 1)}"
  region          = element(var.edge_regions, floor(count.index / var.edge_count_per_region))
  count           = var.edge_count_per_region * length(var.edge_regions)
  size            = var.edge_size
  image           = var.docean_image
  tags            = [var.engagement_name]
  ssh_keys = [digitalocean_ssh_key.key.id]
}
