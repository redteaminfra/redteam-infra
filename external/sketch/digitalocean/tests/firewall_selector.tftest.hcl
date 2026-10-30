# Copyright (c) 2026, Oracle and/or its affiliates.
mock_provider "digitalocean" {
  mock_resource "digitalocean_droplet" {
    defaults = { id = "123456" }
  }
}
mock_provider "local" {}

variables {
  middles = {
    primary = { region = "nyc3", ordinal = 1 }
  }
  edge_groups = {
    sfo = { region = "sfo3", middle_node = "primary", count = 1 }
  }
  docean_image     = "ubuntu-22-04-x64"
  do_pat           = "mock-token"
  engagement_name  = "engagement-test"
  ssh_pub_key_path = "tests/fixtures/id_ed25519.pub"
}

run "legacy_attachments_unchanged" {
  command = apply

  assert {
    condition = (toset(digitalocean_droplet.middle["primary"].tags) == toset(["engagement-test"]) &&
      toset(digitalocean_droplet.edge["sfo3-01"].tags) == toset(["engagement-test"]) &&
      toset(digitalocean_firewall.firewall.tags) == toset(["engagement-test"]) &&
    length(digitalocean_firewall.firewall.droplet_ids) > 0)
    error_message = "An unset selector must preserve legacy engagement tags and explicit Droplet attachments."
  }
}

run "opaque_selector_is_the_only_firewall_attachment" {
  command = apply

  variables {
    firewall_selector_tag = "a1b2c3d4e5f6"
  }

  assert {
    condition = (toset(digitalocean_droplet.middle["primary"].tags) == toset(["a1b2c3d4e5f6"]) &&
      toset(digitalocean_droplet.edge["sfo3-01"].tags) == toset(["a1b2c3d4e5f6"]) &&
      toset(digitalocean_firewall.firewall.tags) == toset(["a1b2c3d4e5f6"]) &&
    length(digitalocean_firewall.firewall.droplet_ids) == 0)
    error_message = "Opted-in Droplets and their firewall must use only the opaque selector tag, never the legacy engagement tag."
  }
}

run "empty_selector_rejected" {
  command = plan
  variables { firewall_selector_tag = "" }
  expect_failures = [var.firewall_selector_tag]
}

run "unsafe_selector_rejected" {
  command = plan
  variables { firewall_selector_tag = "team/engagement name" }
  expect_failures = [var.firewall_selector_tag]
}

run "legacy_engagement_tag_cannot_be_selector" {
  command = plan
  variables { firewall_selector_tag = "engagement-test" }
  expect_failures = [var.firewall_selector_tag]
}
